function fun__shaRounds(var_m_mpos)
            {
                
                let _1 := mload( add(var_m_mpos, 320))
                
                mcopy( 0x2300,  0x2200,  256)
                
                let usr$paddingKey := mload(0x2420)
                mstore(0x2420,  0)
                
                let usr$requested := iszero(iszero(usr$paddingKey))
                let usr$cached := and(usr$requested, eq(usr$paddingKey, mload(0x2440)))
                if usr$cached { mcopy(0x1c00, 0x2460, 1536) }
                let usr$p := add(mul(usr$cached, 1536), 7168)
                for { }
                lt(usr$p,  0x2200)
                
                { usr$p := add(usr$p, 32) }
                {
                    let usr$x := mload(add(usr$p, not(479)))
                    let usr$y := mload(add(usr$p,  not(63)))
                    
                    let usr$wrap_s0 := xor(and(shl(25, usr$x), 0x3f80000001fc0000000fe00000007f00000003f80000001fc0000000fe000000), and(shl(14, usr$x), 0x3ffff00001ffff80000ffffc00007fffe00003ffff00001ffff80000ffffc000))
                    let usr$wrap_s1 := xor(and(shl(15, usr$y), 0x3fffe00001ffff00000ffff800007fffc00003fffe00001ffff00000ffff8000), and(shl(13, usr$y), 0x3ffff80001ffffc0000ffffe00007ffff00003ffff80001ffffc0000ffffe000))
                    mstore(usr$p, and(add(xor(xor(xor(shr(7, usr$x), shr(18, usr$x)), xor(usr$wrap_s0, shr(32, usr$wrap_s0))), shr(3, usr$x)), add(xor(xor(xor(shr(17, usr$y), shr(19, usr$y)), xor(usr$wrap_s1, shr(32, usr$wrap_s1))), and(shr(10, usr$y), 0x0fffffc0007ffffe0003fffff0001fffff8000fffffc0007ffffe0003fffff)), add(mload(add(usr$p,  not(511))),  mload(add(usr$p, not(223)))))),  0x3fffffffc1fffffffe0ffffffff07fffffff83fffffffc1fffffffe0ffffffff))
                }
                
                if and(usr$requested, iszero(usr$cached))
                {
                    mcopy(0x2460, 7168, 1536)
                    mstore(0x2440, usr$paddingKey)
                }
                let usr$a := mload( 0x2300)
                
                let usr$b := mload(8992)
                let usr$c := mload(9024)
                let usr$d := mload(9056)
                let usr$e := mload(9088)
                let usr$f := mload(9120)
                let usr$g := mload(9152)
                let usr$h := mload(9184)
                let usr$p_1 :=  0
                
                for { } lt(usr$p_1, 2048) { usr$p_1 := add(usr$p_1, 32) }
                {
                    let usr$wrap_S1 := xor(and(shl(21, xor(shl(5, usr$e), usr$e)), 0x3ff8000001ffc000000ffe0000007ff0000003ff8000001ffc000000ffe00000), and(shl(7, usr$e), 0x3fffffe001ffffff000ffffff8007fffffc003fffffe001ffffff000ffffff80))
                    let usr$t1 := add(xor(xor(shr(6, usr$e), xor(shr(11, usr$e), shr(25, usr$e))), xor(usr$wrap_S1, shr(32, usr$wrap_S1))), add(xor(usr$g, and(usr$e, xor(usr$f, usr$g))), add(usr$h, add(mload(add( 0x1a00,  usr$p_1)), mload(add( 0x1000,  usr$p_1))))))
                    usr$h := usr$g
                    usr$g := usr$f
                    usr$f := usr$e
                    usr$e := and(add(usr$d, usr$t1),  0x3fffffffc1fffffffe0ffffffff07fffffff83fffffffc1fffffffe0ffffffff)
                    
                    usr$d := usr$c
                    let usr$maj := xor(and(usr$a, usr$b), and(usr$c, xor(usr$a, usr$b)))
                    usr$c := usr$b
                    usr$b := usr$a
                    usr$a := and(add(usr$t1, add(xor(or(shr(2, usr$a), and(shl(30, usr$a), 0x3000000001800000000c000000006000000003000000001800000000c0000000)), xor(or(and(shr(13, usr$a), 0x07ffffc001fffffe000ffffff0007fffff8003fffffc001fffffe000ffffff), and(shl(19, usr$a), 0x3ffe000001fff000000fff8000007ffc000003ffe000001fff000000fff80000)), or(and(shr(22, usr$a), 0x03ffc00000fffe000007fff000003fff800001fffc00000fffe000007fff), and(shl(10, usr$a), 0x3fffff0001fffff8000fffffc0007ffffe0003fffff0001fffff8000fffffc00)))), usr$maj)),  0x3fffffffc1fffffffe0ffffffff07fffffff83fffffffc1fffffffe0ffffffff)
                }
                
                mstore( 0x2300,  usr$a)
                mstore(8992, usr$b)
                mstore(9024, usr$c)
                mstore(9056, usr$d)
                mstore(9088, usr$e)
                mstore(9120, usr$f)
                mstore(9152, usr$g)
                mstore(9184, usr$h)
                
                let usr$i :=  0
                
                for { }
                lt(usr$i,  256)
                
                {
                    usr$i := add(usr$i,  32)
                }
                
                {
                    let _2 := mload(add( 0x2300,  usr$i))
                    let _3 := add( 0x2200,  usr$i)
                    mstore(_3, and(add(mload(_3), _2), _1))
                }
            }
