function fun_shaRounds(var_m_mpos)
            {
                
                let var_packed :=  0
                
                let _1 := mload( add(var_m_mpos, 320))
                
                mcopy( 0x2300,  0x2200,  256)
                
                var_packed :=  0
                
                let usr$p := 7168
                for { }
                lt(usr$p,  0x2200)
                
                { usr$p := add(usr$p, 32) }
                {
                    let usr$x := mload(add(usr$p,  not(479)))
                    
                    let usr$y := mload(add(usr$p,  not(63)))
                    
                    let usr$xx := mul(usr$x, 0x100000001)
                    let usr$yy := mul(usr$y, 0x100000001)
                    mstore(usr$p, and(add(xor(shr(7, usr$xx), xor(shr(18, usr$xx), shr(3, usr$x))), add(xor(shr(17, usr$yy), xor(shr(19, usr$yy), shr(10, usr$y))), add(mload(add(usr$p,  not(511))),  mload(add(usr$p,  not(223)))))),  0xffffffff))
                }
                
                let usr$a := mul(and(mload( 0x2300),  0xffffffff),  0x100000001)
                let usr$b := mul(and(mload(8992),  0xffffffff),  0x100000001)
                let usr$c := mul(and(mload(9024),  0xffffffff),  0x100000001)
                let usr$d := mul(and(mload(9056),  0xffffffff),  0x100000001)
                let usr$e := mul(and(mload(9088),  0xffffffff),  0x100000001)
                let usr$f := mul(and(mload(9120),  0xffffffff),  0x100000001)
                let usr$g := mul(and(mload(9152),  0xffffffff),  0x100000001)
                let usr$h := mul(and(mload(9184),  0xffffffff),  0x100000001)
                let usr$i :=  0
                
                for { } lt(usr$i, 64) { usr$i := add(usr$i, 4) }
                {
                    let _2 := shl(5, usr$i)
                    let usr$t1 := add(xor(shr(6, usr$e), xor(shr(11, usr$e), shr(25, usr$e))), add(xor(usr$g, and(usr$e, xor(usr$f, usr$g))), add(usr$h, add(mload(add( 0x1a00,  _2)), mload(add( 0x1000,  _2))))))
                    let usr$d_1 := mul(and(add(usr$d, usr$t1),  0xffffffff),  0x100000001)
                    let usr$h_1 := mul(and(add(usr$t1, add(xor(shr(2, usr$a), xor(shr(13, usr$a), shr(22, usr$a))), xor(and(usr$a, usr$b), and(usr$c, xor(usr$a, usr$b))))),  0xffffffff),  0x100000001)
                    let _3 := shl(5, add(usr$i, 1))
                    let usr$t1_1 := add(xor(shr(6, usr$d_1), xor(shr(11, usr$d_1), shr(25, usr$d_1))), add(xor(usr$f, and(usr$d_1, xor(usr$e, usr$f))), add(usr$g, add(mload(add( 0x1a00,  _3)), mload(add( 0x1000,  _3))))))
                    let usr$c_1 := mul(and(add(usr$c, usr$t1_1),  0xffffffff),  0x100000001)
                    let usr$g_1 := mul(and(add(usr$t1_1, add(xor(shr(2, usr$h_1), xor(shr(13, usr$h_1), shr(22, usr$h_1))), xor(and(usr$h_1, usr$a), and(usr$b, xor(usr$h_1, usr$a))))),  0xffffffff),  0x100000001)
                    let _4 := shl(5, add(usr$i, 2))
                    let usr$t1_2 := add(xor(shr(6, usr$c_1), xor(shr(11, usr$c_1), shr(25, usr$c_1))), add(xor(usr$e, and(usr$c_1, xor(usr$d_1, usr$e))), add(usr$f, add(mload(add( 0x1a00,  _4)), mload(add( 0x1000,  _4))))))
                    let usr$b_1 := mul(and(add(usr$b, usr$t1_2),  0xffffffff),  0x100000001)
                    let usr$f_1 := mul(and(add(usr$t1_2, add(xor(shr(2, usr$g_1), xor(shr(13, usr$g_1), shr(22, usr$g_1))), xor(and(usr$g_1, usr$h_1), and(usr$a, xor(usr$g_1, usr$h_1))))),  0xffffffff),  0x100000001)
                    let _5 := shl(5, add(usr$i, 3))
                    let usr$t1_3 := add(xor(shr(6, usr$b_1), xor(shr(11, usr$b_1), shr(25, usr$b_1))), add(xor(usr$d_1, and(usr$b_1, xor(usr$c_1, usr$d_1))), add(usr$e, add(mload(add( 0x1a00,  _5)), mload(add( 0x1000,  _5))))))
                    let usr$a_1 := mul(and(add(usr$a, usr$t1_3),  0xffffffff),  0x100000001)
                    usr$a := mul(and(add(usr$t1_3, add(xor(shr(2, usr$f_1), xor(shr(13, usr$f_1), shr(22, usr$f_1))), xor(and(usr$f_1, usr$g_1), and(usr$h_1, xor(usr$f_1, usr$g_1))))),  0xffffffff),  0x100000001)
                    usr$b := usr$f_1
                    usr$c := usr$g_1
                    usr$d := usr$h_1
                    usr$e := usr$a_1
                    usr$f := usr$b_1
                    usr$g := usr$c_1
                    usr$h := usr$d_1
                }
                mstore( 0x2300,  usr$a)
                mstore(8992, usr$b)
                mstore(9024, usr$c)
                mstore(9056, usr$d)
                mstore(9088, usr$e)
                mstore(9120, usr$f)
                mstore(9152, usr$g)
                mstore(9184, usr$h)
                
                let usr$i_1 :=  0
                
                for { }
                lt(usr$i_1,  256)
                
                {
                    usr$i_1 := add(usr$i_1,  32)
                }
                
                {
                    let _6 := mload(add( 0x2300,  usr$i_1))
                    let _7 := add( 0x2200,  usr$i_1)
                    mstore(_7, and(add(mload(_7), _6), _1))
                }
            }
