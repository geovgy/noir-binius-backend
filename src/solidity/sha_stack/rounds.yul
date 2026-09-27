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
