import {CalendarDate, Time} from "@internationalized/date";
import {describe, expect, it} from "vitest";

import {expiryBody, expiryProblem, joinDateTime, shortcutDate, splitDateTime} from "./dateTime.ts";

const TEHRAN = "Asia/Tehran";
const NOW = new Date("2026-11-25T08:00:00Z");

describe("calendar with a clock", () => {
  it("counts a month as 30 days and the others by the clock, as the API does", () => {
    expect(shortcutDate("1h", NOW).toISOString()).toBe("2026-11-25T09:00:00.000Z");
    expect(shortcutDate("1d", NOW).toISOString()).toBe("2026-11-26T08:00:00.000Z");
    expect(shortcutDate("1w", NOW).toISOString()).toBe("2026-12-02T08:00:00.000Z");
    expect(shortcutDate("1m", NOW).toISOString()).toBe("2026-12-25T08:00:00.000Z");
  });

  it("shows an instant in Iran's zone and puts it back unchanged", () => {
    const at = new Date("2026-11-25T08:30:00Z"); // 12:00 in Tehran (UTC+3:30, no daylight saving since 2022)
    const {date, time} = splitDateTime(at, TEHRAN);
    expect([date.year, date.month, date.day, time.hour, time.minute]).toEqual([2026, 11, 25, 12, 0]);
    expect(joinDateTime(date, time, TEHRAN).toISOString()).toBe(at.toISOString());
  });

  it("joins a picked day and clock into the instant in that zone, across midnight in UTC", () => {
    expect(joinDateTime(new CalendarDate(2026, 12, 1), new Time(1, 15), TEHRAN).toISOString()).toBe("2026-11-30T21:45:00.000Z");
  });

  it("judges an expiry as the API does: after now, at most a year ahead", () => {
    expect(expiryProblem(new Date(NOW.getTime() - 1), NOW)).toBe("past");
    expect(expiryProblem(NOW, NOW)).toBe("past");
    expect(expiryProblem(new Date(NOW.getTime() + 1), NOW)).toBeNull();
    expect(expiryProblem(new Date(NOW.getTime() + 365 * 86_400_000), NOW)).toBeNull();
    expect(expiryProblem(new Date(NOW.getTime() + 365 * 86_400_000 + 1), NOW)).toBe("tooFar");
  });

  it("sends a shortcut as expires_in and a picked time as expires_at in UTC, with no milliseconds", () => {
    expect(expiryBody({shortcut: "1d"})).toEqual({expires_in: "1d"});
    expect(expiryBody({at: new Date("2026-12-01T21:45:00.123Z")})).toEqual({expires_at: "2026-12-01T21:45:00Z"});
    expect(expiryBody(null)).toEqual({});
  });
});
