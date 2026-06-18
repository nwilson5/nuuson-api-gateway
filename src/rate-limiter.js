export class RateLimiter {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    const { rpm, rpd } = await request.json();
    const now = Math.floor(Date.now() / 1000);

    const curMinute = Math.floor(now / 60) * 60;
    const prevMinute = curMinute - 60;
    const minuteElapsed = (now - curMinute) / 60;

    const curHour = Math.floor(now / 3600) * 3600;
    const hourElapsed = (now - curHour) / 3600;

    // Fetch 2 minute buckets + 25 hour buckets in one batch
    const stored = await this.state.storage.get([
      `m:${curMinute}`,
      `m:${prevMinute}`,
      ...Array.from({ length: 25 }, (_, i) => `h:${curHour - i * 3600}`),
    ]);

    const curMinuteCount = stored.get(`m:${curMinute}`) ?? 0;
    const prevMinuteCount = stored.get(`m:${prevMinute}`) ?? 0;

    // Sliding RPM: previous minute fades as the current minute progresses
    const rpmEstimate = Math.floor(prevMinuteCount * (1 - minuteElapsed)) + curMinuteCount;

    // Sliding RPD (rolling 24h): edge bucket H-24 is partially in-window;
    // buckets H through H-23 are fully within the 24h window
    const edgeHourCount = stored.get(`h:${curHour - 24 * 3600}`) ?? 0;
    let fullHoursSum = 0;
    for (let i = 0; i < 24; i++) {
      fullHoursSum += stored.get(`h:${curHour - i * 3600}`) ?? 0;
    }
    const rpdEstimate = Math.floor(edgeHourCount * (1 - hourElapsed)) + fullHoursSum;

    const rpmAllowed = rpm === 0 || rpmEstimate < rpm;
    const rpdAllowed = rpd === 0 || rpdEstimate < rpd;
    const allowed = rpmAllowed && rpdAllowed;

    if (allowed) {
      // DO serializes requests per instance — no transaction needed
      await this.state.storage.put(`m:${curMinute}`, curMinuteCount + 1);
      const curHourCount = stored.get(`h:${curHour}`) ?? 0;
      await this.state.storage.put(`h:${curHour}`, curHourCount + 1);
    }

    const reset_rpm = curMinute + 60;

    return new Response(
      JSON.stringify({
        allowed,
        remaining_rpm: rpm === 0 ? null : Math.max(0, rpm - rpmEstimate - (allowed ? 1 : 0)),
        remaining_rpd: rpd === 0 ? null : Math.max(0, rpd - rpdEstimate - (allowed ? 1 : 0)),
        reset_rpm,
      }),
      { headers: { 'content-type': 'application/json' } },
    );
  }
}
