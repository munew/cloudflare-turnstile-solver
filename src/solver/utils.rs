use anyhow::{anyhow, bail};
use chrono::{DateTime, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use rand::prelude::{RngCore, ThreadRng};
use std::ops::Range;

fn js_math_random(rng: &mut ThreadRng) -> f64 {
    let bits = rng.next_u64() >> 11;
    bits as f64 / ((1_u64 << 53) as f64)
}

// dummy float imprecision array
static JS_IMPRECISION: &[f64] = &[
    0.0,
    0.09999999404,
    0.199999988079,
    0.300000011921,
    0.40000000596,
    0.5,
    0.59999999404,
    0.699999988079,
    0.799999982119,
    0.899999976158,
];

pub fn imprecise_performance_now_value(f: f64) -> f64 {
    let first_decimal = f * 10.0 % 10.0;
    f - f.fract() + JS_IMPRECISION[first_decimal as usize]
}

pub fn random_time(rng: &mut ThreadRng, range: Range<f64>) -> f64 {
    let raw = js_math_random(rng) * (range.end - range.start) + range.start;
    let first_decimal = raw * 1.0 % 10.0;

    raw - raw.fract() + first_decimal
}

pub fn diff(rng: &mut ThreadRng, r1: Range<f64>, r2: Range<f64>) -> f64 {
    let t1 = random_time(rng, r1);
    let t2 = random_time(rng, r2);
    t1 - t2
}

pub fn get_utc_offset_for_timezone_on_dec1(year: i32, tz_str: &str) -> Result<i64, anyhow::Error> {
    let tz: Tz = match tz_str.parse() {
        Ok(timezone) => timezone,
        Err(_) => {
            return Err(anyhow!(
                "Invalid or unrecognized timezone string: \"{}\"",
                tz_str
            ));
        }
    };

    let date = match NaiveDate::from_ymd_opt(year, 12, 1) {
        Some(d) => d,
        None => bail!("Failed to create date for year {year}"),
    };

    let time = NaiveTime::from_hms_opt(12, 0, 0).unwrap();
    let naive_dt = NaiveDateTime::new(date, time);

    let datetime_aware: DateTime<Tz> = match tz.from_local_datetime(&naive_dt) {
        LocalResult::Single(dt) => dt,
        LocalResult::Ambiguous(dt1, _) => {
            println!("Warning: Ambiguous local time resolved for {tz_str} at {naive_dt}. Using first interpretation.");
            dt1
        }
        LocalResult::None => {
            bail!("The specific local time {naive_dt} does not exist in timezone \"{tz_str}\"");
        }
    };

    let naive_local = datetime_aware.naive_local();
    let naive_utc = datetime_aware.naive_utc();
    let duration = naive_local - naive_utc;
    let offset_minutes = duration.num_minutes();

    Ok(offset_minutes)
}

pub fn get_timezone_offset(tz_str: &str) -> Result<i64, anyhow::Error> {
    let tz: Tz = match tz_str.parse() {
        Ok(timezone) => timezone,
        Err(_) => {
            return Err(anyhow!(
                "Invalid or unrecognized timezone string: \"{}\"",
                tz_str
            ));
        }
    };

    let now_utc = Utc::now();
    let now_in_tz = now_utc.with_timezone(&tz);
    let naive_local = now_in_tz.naive_local();
    let naive_utc = now_in_tz.naive_utc();
    let duration = naive_local - naive_utc;

    Ok(-duration.num_minutes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_time_js() {
        let mut rng = rand::rng();
        let range = 0.4..0.5;
        let v = random_time(&mut rng, range);
        dbg!(v);
    }
}
