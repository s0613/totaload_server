package com.isoplatform.api.accident;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AccidentType {
    COLLISION("추돌"),
    FLOOD("침수"),
    FIRE("화재"),
    ROLLOVER("전복"),
    OTHER("기타");

    private final String displayName;
}
