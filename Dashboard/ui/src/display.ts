const INVISIBLE_OR_CONTROL = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g;
const ECHARTS_FORMAT_CONTROL = /[{}|\\]/g;

function truncate(value: string, limit: number): string {
  if (!Number.isSafeInteger(limit) || limit < 4) {
    throw new RangeError("display text limits must be safe integers of at least four characters");
  }
  return value.length <= limit ? value : `${value.slice(0, limit - 3)}...`;
}

/**
 * Prepare untrusted projection metadata for bounded, stable text rendering.
 * React still performs the HTML escaping; this only removes invisible controls
 * that can spoof a label or force a layout unexpectedly.
 */
export function displayText(value: string, limit = 256): string {
  return truncate(value.replace(INVISIBLE_OR_CONTROL, " ").replace(/\s+/g, " ").trim(), limit);
}

/** ECharts rich-text syntax must not be sourced from an event projection. */
export function graphText(value: string, limit = 56): string {
  return displayText(value.replace(ECHARTS_FORMAT_CONTROL, " "), limit);
}
