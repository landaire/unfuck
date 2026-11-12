//! Proleptic Gregorian calendar arithmetic on plain integers. Day ordinal 1
//! is 0001-01-01.
//!
//! Dates restored from a pickle state may hold year 0 or day 0. For those the
//! client counts every year before year 1 as a copy of year 0 and takes
//! weekdays with a remainder that keeps the sign of the ordinal; the
//! functions here reproduce that.

/// A calendar date. Fields read from a pickle state may lie outside their
/// usual ranges; only the month is guaranteed to be in 1..=12.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CivilDate {
    pub(super) year: i64,
    pub(super) month: i64,
    pub(super) day: i64,
}

impl CivilDate {
    pub(super) const fn new(year: i64, month: i64, day: i64) -> Self {
        Self { year, month, day }
    }

    /// The day ordinal of this date.
    pub(super) fn ordinal(self) -> i64 {
        year_offset(self.year) + month_offset(self.year, self.month) + self.day
    }

    /// The date of day ordinal `ordinal`, which may lie outside years
    /// 1..=9999.
    pub(super) fn from_ordinal(ordinal: i64) -> Self {
        /// Days in a full 400-year Gregorian cycle.
        const DAYS_PER_CYCLE: i64 = 146_097;

        // Start from the year the mean Gregorian year length suggests, then
        // step until the year contains the ordinal.
        let elapsed = ordinal - 1;
        let mut year = elapsed.div_euclid(DAYS_PER_CYCLE) * 400 + elapsed.rem_euclid(DAYS_PER_CYCLE) * 400 / DAYS_PER_CYCLE + 1;
        while year > 0 && proleptic_year_offset(year) >= ordinal {
            year -= 1;
        }
        while proleptic_year_offset(year + 1) < ordinal {
            year += 1;
        }

        let mut day = ordinal - proleptic_year_offset(year);
        let mut month = 1;
        while month < 12 && day > days_in_month(year, month) {
            day -= days_in_month(year, month);
            month += 1;
        }

        Self { year, month, day }
    }

    /// Day of the week, Monday 0.
    pub(super) fn weekday(self) -> i64 {
        weekday_of(self.ordinal())
    }

    /// Day of the year, January 1 being 1.
    pub(super) fn day_of_year(self) -> i64 {
        month_offset(self.year, self.month) + self.day
    }

    /// The ISO 8601 year, week number, and weekday (Monday 1).
    pub(super) fn iso_calendar(self) -> IsoWeekDate {
        let ordinal = self.ordinal();

        let mut year = self.year;
        let mut offset = ordinal - iso_first_monday(year);
        if offset.div_euclid(7) < 0 {
            year -= 1;
            offset = ordinal - iso_first_monday(year);
        } else if offset.div_euclid(7) >= 52 && ordinal >= iso_first_monday(year + 1) {
            year += 1;
            offset = offset.rem_euclid(7);
        }

        IsoWeekDate { year, week: offset.div_euclid(7) + 1, weekday: offset.rem_euclid(7) + 1 }
    }
}

/// A date in the ISO 8601 week calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IsoWeekDate {
    pub(super) year: i64,
    pub(super) week: i64,
    pub(super) weekday: i64,
}

pub(super) fn is_leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// Days in `month` (1..=12) of `year`; 0 for any other month.
pub(super) fn days_in_month(year: i64, month: i64) -> i64 {
    const MONTH_LENGTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let Some(length) = usize::try_from(month - 1).ok().and_then(|index| MONTH_LENGTHS.get(index)) else {
        return 0;
    };

    if month == 2 && is_leap(year) { length + 1 } else { *length }
}

/// Day of the week of `ordinal`, Monday 0, negative before ordinal -5.
fn weekday_of(ordinal: i64) -> i64 {
    (ordinal + 6) % 7
}

/// Days in the months of `year` before `month` (1..=12).
fn month_offset(year: i64, month: i64) -> i64 {
    (1..month.clamp(1, 13)).map(|earlier| days_in_month(year, earlier)).sum()
}

/// Days in the years before `year`, with years before 1 counted as year 0.
fn year_offset(year: i64) -> i64 {
    proleptic_year_offset(year.max(0))
}

/// Days in the years before `year`, counted from year 1.
fn proleptic_year_offset(year: i64) -> i64 {
    let previous = year - 1;

    previous * 365 + previous.div_euclid(4) - previous.div_euclid(100) + previous.div_euclid(400)
}

/// The ordinal of the Monday that starts ISO week 1 of `year`: the Monday
/// on or before January 1 when January 1 falls Monday to Thursday, else the
/// Monday after it.
fn iso_first_monday(year: i64) -> i64 {
    let january_first = year_offset(year) + 1;
    let weekday = weekday_of(january_first);

    if weekday > 3 { january_first - weekday + 7 } else { january_first - weekday }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinals_round_trip() {
        for ordinal in (1..4_000_000).step_by(997) {
            assert_eq!(CivilDate::from_ordinal(ordinal).ordinal(), ordinal);
        }
        assert_eq!(CivilDate::from_ordinal(1), CivilDate::new(1, 1, 1));
        assert_eq!(CivilDate::from_ordinal(0), CivilDate::new(0, 12, 31));
        assert_eq!(CivilDate::from_ordinal(3_652_059), CivilDate::new(9999, 12, 31));
        assert_eq!(CivilDate::from_ordinal(3_652_060), CivilDate::new(10000, 1, 1));
        assert_eq!(CivilDate::new(2000, 2, 29).ordinal(), 730_179);
    }

    #[test]
    fn iso_weeks_cross_year_boundaries() {
        assert_eq!(CivilDate::new(2003, 12, 29).iso_calendar(), IsoWeekDate { year: 2004, week: 1, weekday: 1 });
        assert_eq!(CivilDate::new(2005, 1, 2).iso_calendar(), IsoWeekDate { year: 2004, week: 53, weekday: 7 });
        assert_eq!(CivilDate::new(9999, 12, 31).iso_calendar(), IsoWeekDate { year: 9999, week: 52, weekday: 5 });
    }

    #[test]
    fn year_zero_states_follow_the_client() {
        assert_eq!(CivilDate::new(0, 1, 0).ordinal(), -366);
        assert_eq!(CivilDate::new(0, 1, 0).weekday(), -3);
        assert_eq!(CivilDate::new(0, 1, 0).iso_calendar(), IsoWeekDate { year: -1, week: 0, weekday: 5 });
        assert_eq!(CivilDate::new(0, 3, 1).iso_calendar(), IsoWeekDate { year: 0, week: 9, weekday: 3 });
        assert_eq!(CivilDate::new(1, 1, 0).iso_calendar(), IsoWeekDate { year: 0, week: 52, weekday: 7 });
        assert_eq!(CivilDate::new(65535, 12, 31).iso_calendar(), IsoWeekDate { year: 65536, week: 1, weekday: 2 });
    }
}
