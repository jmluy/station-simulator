package com.evbox.everon.ocpp.simulator.station;

import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
@FieldDefaults(makeFinal = true)
public class HeartbeatScheduler {

    private HeartbeatSenderTask heartbeatTask;
    private ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();

    public HeartbeatScheduler(StationState stationState, StationMessageSender stationMessageSender) {
        this.heartbeatTask = new HeartbeatSenderTask(stationState, stationMessageSender);
    }

    public void updateHeartbeat(int heartbeatInterval) {
        log.debug("Updating heartbeat to {} sec.", heartbeatInterval);
        heartbeatTask.updateHeartBeatInterval(heartbeatInterval);
        scheduledExecutorService.scheduleAtFixedRate(
                heartbeatTask, heartbeatInterval, heartbeatInterval, TimeUnit.SECONDS);
    }
}
