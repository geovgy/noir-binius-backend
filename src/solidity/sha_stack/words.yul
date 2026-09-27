let usr$x := mload(add(usr$p, not(479)))
                    let usr$y := mload(add(usr$p,  not(63)))
                    
                    let usr$wrap_s0 := xor(and(shl(25, usr$x), 0x3f80000001fc0000000fe00000007f00000003f80000001fc0000000fe000000), and(shl(14, usr$x), 0x3ffff00001ffff80000ffffc00007fffe00003ffff00001ffff80000ffffc000))
                    let usr$wrap_s1 := xor(and(shl(15, usr$y), 0x3fffe00001ffff00000ffff800007fffc00003fffe00001ffff00000ffff8000), and(shl(13, usr$y), 0x3ffff80001ffffc0000ffffe00007ffff00003ffff80001ffffc0000ffffe000))
                    mstore(usr$p, and(add(xor(xor(xor(shr(7, usr$x), shr(18, usr$x)), xor(usr$wrap_s0, shr(32, usr$wrap_s0))), shr(3, usr$x)), add(xor(xor(xor(shr(17, usr$y), shr(19, usr$y)), xor(usr$wrap_s1, shr(32, usr$wrap_s1))), and(shr(10, usr$y), 0x0fffffc0007ffffe0003fffff0001fffff8000fffffc0007ffffe0003fffff)), add(mload(add(usr$p,  not(511))),  mload(add(usr$p, not(223)))))),  0x3fffffffc1fffffffe0ffffffff07fffffff83fffffffc1fffffffe0ffffffff))
