use std::time::Duration;

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
struct LatencySample {
    time: i64,
    latency: Duration,
}

impl Default for LatencySample {
    fn default() -> Self {
        Self {
            time: chrono::Utc::now().timestamp(),
            latency: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkMeter {
    bandwidth_samples: [BandwidthSample; 5],
    latency_samples: [LatencySample; 3],
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

    pub fn note_latency(&mut self, time: i64, latency: Duration) {
        let mut sample = self.get_latency_sample_mut(time);
        sample.latency = sample.latency + latency / 2
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

    fn get_latency_sample_mut(&mut self, time: i64) -> &mut LatencySample {
        if self.latency_samples[0].time == time {
            &mut self.latency_samples[0]
        } else {
            let mut data = [LatencySample::default(); 2];
            data.copy_from_slice(&self.latency_samples[0..2]);
            let _ = &self.latency_samples[1..3].copy_from_slice(&data);
            self.latency_samples[0] = self.latency_samples[1];
            &mut self.latency_samples[0]
        }
    }

    pub fn new() -> Self {
        Self {
            bandwidth_samples: [BandwidthSample::default(); 5],
            latency_samples: [LatencySample::default(); 3],
        }
    }
}
