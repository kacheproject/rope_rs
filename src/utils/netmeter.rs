use arrayvec::ArrayVec;
use average::MeanWithError;
use itertools::Itertools;

#[derive(Clone, Copy, Debug)]
struct BandwidthSample {
    time: i64,
    rx_bytes: usize,
    tx_bytes: usize,
}

impl Default for BandwidthSample {
    fn default() -> Self {
        Self {
            time: chrono::Utc::now().timestamp(),
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StatusChange {
    Avaliable(i64),
    Unavaliable(i64),
}

#[derive(Clone)]
pub struct NetworkMeter {
    bandwidth_samples: [BandwidthSample; 5],
    status_samples: ArrayVec<StatusChange, 64>,
}

impl std::fmt::Debug for NetworkMeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (bw_rx, bw_tx) = self.get_bandwidth();
        let availablity = self.get_availability();
        f.write_fmt(format_args!("NetworkMeter {{ bandwidth_rx: {}, bandwidth_tx: {}, availability: {} }}", bw_rx, bw_tx, availablity))
    }
}

impl NetworkMeter {
    pub fn note_rx(&mut self, time: i64, rx_bytes: usize) {
        let mut sample = self.get_bandwidth_sample_mut(time);
        sample.rx_bytes += rx_bytes;
    }

    pub fn note_tx(&mut self, time: i64, tx_bytes: usize) {
        let mut sample = self.get_bandwidth_sample_mut(time);
        sample.tx_bytes += tx_bytes;
    }

    pub fn note_avaliable(&mut self, time: i64) {
        if let Some(elmut) = self.status_samples.last_mut() {
            if let StatusChange::Avaliable(t) = elmut {
                if time > *t {
                    *t = time;
                }
                return;
            }
        }
        if self.status_samples.remaining_capacity() == 0 {
            self.status_samples.pop_at(0);
        }
        self.status_samples.push(StatusChange::Avaliable(time));
    }

    pub fn note_unavaliable(&mut self, time: i64) {
        if let Some(elmut) = self.status_samples.last_mut() {
            if let StatusChange::Unavaliable(t) = elmut {
                if time > *t {
                    *t = time;
                }
                return;
            }
        }
        if self.status_samples.remaining_capacity() == 0 {
            self.status_samples.pop_at(0);
        }
        self.status_samples.push(StatusChange::Unavaliable(time));
    }

    pub fn get_availability(&self) -> f64 {
        use StatusChange::*;
        let mut tbf: ArrayVec<i32, 32> = ArrayVec::new();
        let mut ttr: ArrayVec<i32, 32> = ArrayVec::new();
        for (s0, s1) in self.status_samples.iter().tuples() {
            match (s0, s1) {
                (Unavaliable(t0), Avaliable(t1)) => {
                    let duration = t1 - t0;
                    ttr.push(if duration > i32::MAX.into() {
                        i32::MAX
                    } else {
                        duration.try_into().unwrap()
                    });
                },
                (Avaliable(t0), Unavaliable(t1)) => {
                    let duration = t1 - t0;
                    tbf.push(if duration > i32::MAX.into() {
                        i32::MAX
                    } else {
                        duration.try_into().unwrap()
                    });
                }
                _ => {},
            }
        }
        let mtbf: f64 = tbf.iter().map::<f64, _>(|v| v.to_owned().into()).collect::<MeanWithError>().mean();
        let mttr: f64 = tbf.iter().map::<f64, _>(|v| v.to_owned().into()).collect::<MeanWithError>().mean();
        mtbf / (mtbf + mttr)
    }

    /// Return bandwidth in (rx, tx) form. The bandwidth is the average of 5-second samples.
    /// Note that the bandwidth measured by this meter may be less than actual bandwidth, since the data depends on data transfered.
    /// To measure actual bandwidth, you need to fill the wire at least 5 seconds.
    pub fn get_bandwidth(&self) -> (usize, usize) {
        (self.get_bandwidth_sample_rx() / self.bandwidth_samples.len(), self.get_bandwidth_sample_tx() / self.bandwidth_samples.len())
    }

    fn get_bandwidth_sample_rx(&self) -> usize {
        let mut rx = 0;
        for sample in &self.bandwidth_samples {
            rx += sample.rx_bytes;
        }
        rx
    }

    fn get_bandwidth_sample_tx(&self) -> usize {
        let mut tx = 0;
        for sample in &self.bandwidth_samples {
            tx += sample.tx_bytes;
        }
        tx
    }

    fn get_bandwidth_sample_mut(&mut self, time: i64) -> &mut BandwidthSample {
        if self.bandwidth_samples[0].time != time {
            let mut data = [BandwidthSample::default(); 4];
            data.copy_from_slice(&self.bandwidth_samples[0..4]);
            let _ = &self.bandwidth_samples[1..5].copy_from_slice(&data);
            self.bandwidth_samples[0] = BandwidthSample::default();
            &mut self.bandwidth_samples[0]
        } else {
            &mut self.bandwidth_samples[0]
        }
    }

    pub fn new() -> Self {
        let status_samples = ArrayVec::new();
        Self {
            bandwidth_samples: [BandwidthSample::default(); 5],
            status_samples,
        }
    }
}
