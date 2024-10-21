rule FullDetection
{
    strings:
        $hex1 = { 02 00 00 A0 }
        $hex2 = { 04 00 00 A0 }
        $hex3 = { 06 00 00 A0 }
        $hex4 = { 01 00 00 A0 }
        $hex5 = { 07 00 00 A0 }
        $hex6 = { 0B 00 00 A0 }
        $hex7 = { 09 00 00 A0 }
        $hex8 = { 08 00 00 A0 }
        $hex9 = { 05 00 00 A0 }
        $hex10 = { 03 00 00 A0 }
        $hex11 = { 0C 00 00 A0 }

    condition:
        not any of ($hex*)  // 주어진 HEX 값들이 모두 존재하지 않는 경우에 매칭
}