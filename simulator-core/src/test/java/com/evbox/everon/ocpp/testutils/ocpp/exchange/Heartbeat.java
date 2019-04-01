package com.evbox.everon.ocpp.testutils.ocpp.exchange;

import com.evbox.everon.ocpp.simulator.message.ActionType;
import com.evbox.everon.ocpp.simulator.message.Call;
import com.evbox.everon.ocpp.testutils.factory.JsonMessageTypeFactory;

import java.time.ZonedDateTime;
import java.util.function.Function;
import java.util.function.Predicate;

public class Heartbeat extends Exchange {

    /**
     * HeartbeatRequest with any configuration.
     *
     * @@return checks whether an incoming request is HeartbeatRequest or not.
     */
    public static Predicate<Call> request() {
        return request -> equalsType(request, ActionType.HEARTBEAT);
    }

    /**
     * Create a HeartbeatResponse with given timestamp.
     *
     * @param serverTime time of the server
     * @return response in json.
     */
    public static Function<Call, String> response(ZonedDateTime serverTime) {
        return incomingRequest -> JsonMessageTypeFactory.createCallResult()
                .withMessageId(incomingRequest.getMessageId())
                .withCurrentTime(serverTime.toString())
                .toJson();
    }
}
