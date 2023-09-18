use std::str::FromStr;
use num_bigint::{BigInt};

pub fn public() -> (BigInt, BigInt, i32, i32) {
  (
    //BigInt::from_str("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559").unwrap(),
    BigInt::from_str("23").unwrap(),
    BigInt::from_str("11").unwrap(),
    4,
    9
    //BigInt::from_bytes_be(Sign::Plus,
    //  b"\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2!h\xc24\xc4\xc6b\x8b\x80\xdc\x1c\xd1)\x02N\x08\x8ag\xcct\x02\x0b\xbe\xa6;\x13\x9b\"QJ\x08y\x8e4\x04\xdd\xef\x95\x19\xb3\xcd:C\x1b0+\nm\xf2_\x147O\xe15mmQ\xc2E\xe4\x85\xb5vb^~\xc6\xf4LB\xe9\xa67\xedk\x0b\xff\\\xb6\xf4\x06\xb7\xed\xee8k\xfbZ\x89\x9f\xa5\xae\x9f$\x11|K\x1f\xe6I(fQ\xec\xe4[=\xc2\x00|\xb8\xa1c\xbf\x05\x98\xdaH6\x1cU\xd3\x9ai\x16?\xa8\xfd$\xcf_\x83e]#\xdc\xa3\xad\x96\x1cb\xf3V \x85R\xbb\x9e\xd5)\x07p\x96\x96mg\x0c5NJ\xbc\x98\x04\xf1tl\x08\xca\x18!|2\x90^F.6\xce;\xe3\x9ew,\x18\x0e\x86\x03\x9b\'\x83\xa2\xec\x07\xa2\x8f\xb5\xc5]\xf0oLR\xc9\xde+\xcb\xf6\x95X\x17\x189\x95I|\xea\x95j\xe5\x15\xd2&\x18\x98\xfa\x05\x10\x15r\x8eZ\x8a\xac\xaah\xff\xff\xff\xff\xff\xff\xff\xff"),
    //BigInt::from_bytes_be(Sign::Plus,
    //  b"\x7f\xff\xff\xff\xff\xff\xff\xff\xe4\x87\xedQ\x10\xb4a\x1abc1E\xc0n\x0eh\x94\x81\'\x04E3\xe6:\x01\x05\xdfS\x1d\x89\xcd\x91(\xa5\x04<\xc7\x1a\x02n\xf7\xca\x8c\xd9\xe6\x9d!\x8d\x98\x15\x856\xf9/\x8a\x1b\xa7\xf0\x9a\xb6\xb6\xa8\xe1\"\xf2B\xda\xbb1/?cz&!t\xd3\x1b\xf6\xb5\x85\xff\xae[z\x03[\xf6\xf7\x1c5\xfd\xadD\xcf\xd2\xd7O\x92\x08\xbe%\x8f\xf3$\x943(\xf6r-\x9e\xe1\x00>\\P\xb1\xdf\x82\xccm$\x1b\x0e*\xe9\xcd4\x8b\x1f\xd4~\x92g\xaf\xc1\xb2\xae\x91\xeeQ\xd6\xcb\x0e1y\xab\x10B\xa9]\xcfj\x94\x83\xb8KK6\xb3\x86\x1a\xa7%^L\x02x\xba6\x04e\x0c\x10\xbe\x19H/#\x17\x1bg\x1d\xf1\xcf;\x96\x0c\x07C\x01\xcd\x93\xc1\xd1v\x03\xd1G\xda\xe2\xae\xf87\xa6)d\xef\x15\xe5\xfbJ\xac\x0b\x8c\x1c\xca\xa4\xbeuJ\xb5r\x8a\xe9\x13\x0cL}\x02\x88\n\xb9G-EVU4\x7f\xff\xff\xff\xff\xff\xff\xff"),
    //2,
    //4
  )
}