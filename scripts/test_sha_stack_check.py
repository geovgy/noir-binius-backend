"""Negative tests for the independent runtime/source provenance checks."""
import unittest

from sha_stack_check import DATA, load_block, validate_runtime, validate_source


class BindingTests(unittest.TestCase):
    def test_retained_rounds_bind_all_masks_and_output_layouts(self):
        import json
        import sha_pair_stack_check as pair
        masks = pair.round_masks()
        layout = json.loads((DATA/'round-sigma-orders.json').read_text())
        pair.checked_round_parts(load_block(retained=True))
        before = layout['entry']
        for stage, after in enumerate(layout['outputs']):
            code = pair.asm(f'round-retained-{stage}.asm')
            for wrong in [masks[::-1], masks[:-1]+[masks[-1]^1]]:
                with self.assertRaises(AssertionError):
                    pair.check_round_body(code, before, after, stage, wrong)
            with self.assertRaises(AssertionError):
                pair.check_round_body(code, before, after[::-1], stage, masks)
            before = after

    def test_predecessor_words_bind_pair_order_cache_and_block_boundaries(self):
        import sha_pair_stack_check as pair
        from pathlib import Path
        from unittest.mock import patch
        for stage in range(8):
            code = pair.word_body(stage)
            pair.check_word_body(code,stage)
            for wrong in [code[:-1], code[:-1]+b'\x91']:
                with self.assertRaises(AssertionError):
                    pair.check_word_body(wrong,stage)
            with self.assertRaises(AssertionError):
                pair.check_word_body(code,(stage+1)%8)
        block = pair.load_word()
        with self.assertRaises(AssertionError):
            pair.execute(block,{},2)
        read_text = Path.read_text
        for at in [1,6,91,94,97,101,103,104,197,874,877,880,886,888,891,899,900]:
            changed = bytearray(block)
            changed[at] ^= 1
            def read(path, *args, **kwargs):
                return changed.hex() if path.name=='word-pair-block.hex' else read_text(path,*args,**kwargs)
            with patch.object(Path,'read_text',read):
                with self.assertRaises(AssertionError): pair.load_word()

    def test_word_groups_bind_all_four_equations_and_retained_masks(self):
        import sha_word_group_check as groups
        retained = groups.masks()
        for stage in range(4):
            code = groups.body(stage)
            facts = groups.check_body(code, retained, stage)
            self.assertEqual(facts['max_owned_stack'], 13)
            with self.assertRaises(AssertionError):
                groups.check_body(code, retained, (stage+1) % 4)
            wrong = retained[:]
            wrong[-1] ^= 1
            with self.assertRaises(AssertionError):
                groups.check_body(code, wrong, stage)
        with self.assertRaises(AssertionError):
            groups.execute(groups.load_block(), {}, 2)

    def test_word_group_prefix_bodies_branches_and_cleanup_are_pinned(self):
        from pathlib import Path
        from unittest.mock import patch
        import sha_word_group_check as groups
        block = groups.load_block()
        read_text = Path.read_text
        for at in [1, 2, 6, 40, 43, 44, 179, 181, 277, 377, 474, 575, 579, 583, 588, 595]:
            changed = bytearray(block)
            changed[at] ^= 1
            def read(path, *args, **kwargs):
                return changed.hex() if path.name == 'word-group-block.hex' else read_text(path, *args, **kwargs)
            with patch.object(Path, 'read_text', read):
                with self.assertRaises(AssertionError):
                    groups.load_block()

    def test_group_cursor_checks_each_layout_address_and_cursor_update(self):
        import json
        from sha_stack_check import (absolute_cursor_reference, checked_group_parts, check_group_body,
                                     group_body, group_cursor_reference, parse_round)
        block = load_block(group=True)
        _, _, facts = checked_group_parts(block)
        self.assertEqual(facts, dict(group_gas=1245, max_owned_stack=16))
        layout = json.loads((DATA / 'round-group-orders.json').read_text())
        before = layout['entry']
        for stage, after in enumerate(layout['outputs']):
            body = group_body(stage)
            check_group_body(body, before, after, stage)
            with self.assertRaises(AssertionError):
                check_group_body(body, before, after, (stage+1) % 4)
            wrong = after[:]
            wrong[0], wrong[-1] = wrong[-1], wrong[0]
            with self.assertRaises(AssertionError):
                check_group_body(body, before, wrong, stage)
            before = after
        reference = absolute_cursor_reference(parse_round((DATA / 'rounds.yul').read_text()))
        for wrong in [reference | {'p': ('add', 'p', 64)}, reference | {'a': ('mload', 0x1a01)}]:
            with self.assertRaises(AssertionError):
                group_cursor_reference(wrong, 0)
        for stage in [-1, 4]:
            with self.assertRaises(AssertionError):
                group_cursor_reference(reference, stage)
        with self.assertRaises(AssertionError):
            load_block(four=True, group=True)

    def test_shared_scalar_core_requires_complete_functions_and_explicit_binding(self):
        for group, word_loop, sigma, word_group, pair in [(False, False, False, False, False), (True, False, False, False, False),
                                                   (True, True, False, False, False), (True, True, True, False, False),
                                                   (True, True, True, True, False), (True, True, False, False, True)]:
            from sha_word_stack_check import load_block as load_words
            from sha_word_loop_check import load_block as load_loop
            from sha_word_group_check import load_block as load_word_group
            from sha_pair_stack_check import load_word as load_pair
            rounds = (DATA / 'rounds.yul').read_text()
            schedule = (DATA / ('word-loop.yul' if word_loop else 'words.yul')).read_text()
            block = load_block(retained=True) if pair else load_block(sigma=True) if sigma else load_block(group=True) if group else load_block(four=True)
            words = load_pair() if pair else load_word_group() if word_group else load_loop(sigma) if word_loop else load_words(True)
            call = 'verbatim_0i_0o(hex"' + block.hex() + '")'
            argument = 'usr$cached' if word_loop else 'usr$p'
            word_call = 'verbatim_1i_0o(hex"' + words.hex() + '", ' + argument + ')'
            for scalar, packed in [('fun_shaRounds', 'fun__shaRounds'), ('fun__shaRounds', 'fun_shaRounds')]:
                old = (DATA / 'scalar-rounds.yul').read_text().replace('fun_shaRounds', scalar, 1).strip()
                callee = (DATA / 'packed-rounds.yul').read_text().replace('fun__shaRounds', packed, 1).strip()
                reference = 'object "C" { code {} object "C_deployed" { code { ' + old + callee + ' } } }'
                # Production substitutions ignore whitespace and comments. Apply
                # the same exact token substitutions in this synthetic fixture.
                from sha_stack_check import runtime_tokens
                tokens = lambda s: runtime_tokens('object "C_deployed" { ' + s + ' }')[1:-1]
                callee_tokens = tokens(callee)
                for needle, replacement in [(tokens(rounds), tokens(call)), (tokens(schedule), tokens(word_call))]:
                    sites = [i for i in range(len(callee_tokens)-len(needle)+1) if callee_tokens[i:i+len(needle)] == needle]
                    self.assertEqual(len(sites), 1)
                    i = sites[0]
                    callee_tokens[i:i+len(needle)] = replacement
                wrapper = f'function {scalar}(var_m_mpos) {{ mstore(0x2420, 0) {packed}(var_m_mpos) }}'
                emitted_callee = ' '.join(callee_tokens).replace(' '.join(tokens(call)), call).replace(' '.join(tokens(word_call)), word_call)
                emitted = 'object "C" { code {} object "C_deployed" { code { ' + wrapper + emitted_callee + ' } } }'
                validate_source(reference, emitted, words, block, 'packed')
                for bad in [emitted.replace('mstore(0x2420, 0)', ''),
                            emitted.replace('mstore(0x2420, 0)', 'mstore(0x2420, 1)'),
                            emitted.replace(wrapper, wrapper + wrapper),
                            emitted.replace(wrapper, wrapper.replace(packed + '(', scalar + '(')),
                            emitted.replace('and ( add', 'xor ( add'),
                            emitted.replace(wrapper, wrapper + 'mstore(0, 1)')]:
                    self.assertNotEqual(bad, emitted)
                    with self.assertRaises(AssertionError):
                        validate_source(reference, bad, words, block, 'packed')
                for tag in [None, 'scalar']:
                    with self.assertRaises(AssertionError):
                        validate_source(reference, emitted, words, block, tag)
                with self.assertRaises(AssertionError):
                    validate_source(reference, emitted, words, load_block(cursor=True), 'packed')
                if word_loop:
                    for old, new in [('and ( usr$requested', 'xor ( usr$requested'),
                                     ('mcopy ( 0x1c00 , 0x2460 , 1536 )', 'mcopy ( 0x1c00 , 0x2460 , 1504 )'),
                                     (word_call, word_call.replace('usr$cached', 'usr$paddingKey'))]:
                        bad = emitted.replace(old, new)
                        self.assertNotEqual(bad, emitted)
                        with self.assertRaises(AssertionError):
                            validate_source(reference, bad, words, block, 'packed')
            code = bytes.fromhex('6101c0604052') + block + words + bytes.fromhex('00fea00001')
            validate_runtime(code, '0;0;0;0;0;0', block, words)
            for op in (0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff):
                bad = bytearray(code)
                bad[6 + len(block) + len(words)] = op
                with self.assertRaises(AssertionError):
                    validate_runtime(bad, '0;0;0;0;0;0', block, words)

    def test_word_loop_rejects_mutated_branches_bounds_and_body(self):
        import sha_word_loop_check as loop
        from unittest.mock import patch
        for double in (False, True):
            block = loop.load_block(double)
            positions = [1, 2, 8, 9, 11, 298, 300, 305, 308, 309, len(block)-1]
            if double:
                positions += [301, 302, 303, 590, 592, 597, 600, 601]
            for at in positions:
                changed = bytearray(block)
                changed[at] ^= 1
                with patch('pathlib.Path.read_text', return_value=changed.hex()):
                    with self.assertRaises(AssertionError):
                        loop.load_block(double)
            with self.assertRaises(AssertionError):
                loop.execute(block, {}, 2, double)

    def test_sigma_rounds_bind_guard_bits_new_masks_and_stack_peak(self):
        import json
        from sha_stack_check import checked_group_parts, check_group_body, group_body
        block = load_block(sigma=True)
        self.assertEqual(checked_group_parts(block)[2], dict(group_gas=1245, max_owned_stack=17))
        layout = json.loads((DATA/'round-sigma-orders.json').read_text())
        before = layout['entry']
        for stage, after in enumerate(layout['outputs']):
            body = group_body(stage, sigma=True)
            check_group_body(body, before, after, stage, sigma=True)
            for wrong_stage, wrong_sigma in [(stage, False), ((stage+1) % 4, True)]:
                with self.assertRaises(AssertionError):
                    check_group_body(body, before, after, wrong_stage, wrong_sigma)
            before = after
        with self.assertRaises(AssertionError):
            load_block(group=True, sigma=True)

    def test_word_order_changes_only_the_bound_word_block(self):
        from sha_word_stack_check import load_block as load_words
        rounds = (DATA / 'rounds.yul').read_text()
        schedule = (DATA / 'words.yul').read_text()
        reference = ('object "C" { code {} object "C_deployed" { code { '
                     'function sha() { ' + schedule + rounds + ' } } } }')
        block, words = load_block(cursor=True), load_words(True)
        source = reference.replace(rounds, 'verbatim_0i_0o(hex"' + block.hex() + '")')
        source = source.replace(schedule, 'verbatim_1i_0o(hex"' + words.hex() + '", usr$p)')
        validate_source(reference, source, words, block)
        code = bytes.fromhex('6101c0604052') + block + words + bytes.fromhex('00fea00001')
        validate_runtime(code, '0;0;0;0;0;0', block, words)
        with self.assertRaises(AssertionError):
            validate_source(reference, source, load_words(), block)
        with self.assertRaises(AssertionError):
            validate_source(reference.replace('not(479)', 'not(478)'), source, words, block)
        damaged = bytearray(words)
        damaged[0] ^= 1
        with self.assertRaises(AssertionError):
            validate_runtime(code.replace(words, damaged), '0;0;0;0;0;0', block, bytes(damaged))
        for op in (0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff):
            bad = bytearray(code)
            bad[6 + len(block) + len(words)] = op
            with self.assertRaises(AssertionError):
                validate_runtime(bad, '0;0;0;0;0;0', block, words)

    def test_absolute_cursor_checks_loop_bound_reads_and_binding(self):
        from sha_stack_check import absolute_cursor_reference, parse_round
        from sha_word_stack_check import load_block as load_words
        rounds = (DATA / 'rounds.yul').read_text()
        schedule = (DATA / 'words.yul').read_text()
        reference = ('object "C" { code {} object "C_deployed" { code { '
                     'function sha() { ' + schedule + rounds + ' } } } }')
        words, block = load_words(), load_block(cursor=True)
        source = reference.replace(rounds, 'verbatim_0i_0o(hex"' + block.hex() + '")')
        source = source.replace(schedule, 'verbatim_1i_0o(hex"' + words.hex() + '", usr$p)')
        validate_source(reference, source, words, block)
        code = bytes.fromhex('6101c0604052') + block + words + bytes.fromhex('00fea00001')
        validate_runtime(code, '0;0;0;0;0;0', block, words)
        for legacy in (load_block(), load_block(True)):
            with self.assertRaises(AssertionError):
                validate_source(reference, source, words, legacy)
        for old, new in [('2048', '2016'), ('0x1000', '0x1001')]:
            with self.assertRaises(AssertionError):
                validate_source(reference.replace(old, new), source, words, block)
        with self.assertRaises(AssertionError):
            absolute_cursor_reference(parse_round(rounds.replace('0x1a00', '0x1a01')))

    def test_placement_preserves_legacy_binding_and_checks_the_new_block(self):
        from sha_word_stack_check import load_block as load_words
        rounds = (DATA / 'rounds.yul').read_text()
        schedule = (DATA / 'words.yul').read_text()
        reference = ('object "C" { code {} object "C_deployed" { code { '
                     'function sha() { ' + schedule + rounds + ' } } } }')
        words = load_words()
        for placement in (False, True):
            block = load_block(placement)
            call = 'verbatim_0i_0o(hex"' + block.hex() + '")'
            word_call = 'verbatim_1i_0o(hex"' + words.hex() + '", usr$p)'
            source = reference.replace(rounds, call).replace(schedule, word_call)
            validate_source(reference, source, words, block)
            code = bytes.fromhex('6101c0604052') + block + words + bytes.fromhex('00fea00001')
            validate_runtime(code, '0;0;0;0;0;0', block, words)
            with self.assertRaises(AssertionError):
                validate_source(reference, source, words, load_block(not placement))
            damaged = bytearray(block)
            damaged[-1] ^= 1
            with self.assertRaises(AssertionError):
                validate_runtime(code.replace(block, damaged), '0;0;0;0;0;0', bytes(damaged), words)

    def test_source_binding_checks_the_entire_runtime(self):
        rounds = (DATA / 'rounds.yul').read_text()
        reference = ('object "C" { code { mstore(0, 1) } object "C_deployed" { '
                     'code { function sha() { ' + rounds + ' } } } }')
        call = 'verbatim_0i_0o(hex"' + load_block().hex() + '")'
        emitted = reference.replace(rounds, call)
        validate_source(reference, emitted)
        validate_source(reference, emitted.replace('mstore(0, 1)', 'mstore(0, 2)'))
        for bad in [emitted.replace(call, call + '\nmstore(0, 1)'),
                    emitted.replace(call, call + call),
                    emitted.replace('function sha()', 'function changed()')]:
            with self.assertRaises(AssertionError):
                validate_source(reference, bad)
        with self.assertRaises(AssertionError):
            validate_source(reference.replace('shr(6,', 'shr(5,'), emitted)

    def test_source_map_does_not_hide_forbidden_or_unmapped_code(self):
        block = load_block()
        # Entry allocation, exact block, STOP, INVALID, empty-map metadata.
        code = bytes.fromhex('6101c0604052') + block + bytes.fromhex('00fea00001')
        source_map = '0;0;0;0;0'
        validate_runtime(code, source_map, block)
        for op in (0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff):
            bad = bytearray(code)
            bad[6 + len(block)] = op
            with self.assertRaises(AssertionError):
                validate_runtime(bad, source_map, block)
        for bad in [code[:3] + b'\x5b' + code[4:], code[:-4] + b'\x5b' + code[-3:]]:
            with self.assertRaises(AssertionError):
                validate_runtime(bad, source_map, block)
        with self.assertRaises(AssertionError):
            validate_runtime(code, '0;0;0;0', block)

    def test_word_kernel_requires_exact_runtime_and_both_map_entries(self):
        from sha_word_stack_check import load_block as load_words
        block, words = load_block(), load_words()
        rounds = (DATA / 'rounds.yul').read_text()
        schedule = (DATA / 'words.yul').read_text()
        reference = ('object "C" { code {} object "C_deployed" { code { '
                     'function sha() { ' + schedule + rounds + ' } } } }')
        round_call = 'verbatim_0i_0o(hex"' + block.hex() + '")'
        word_call = 'verbatim_1i_0o(hex"' + words.hex() + '", usr$p)'
        emitted = reference.replace(rounds, round_call).replace(schedule, word_call)
        validate_source(reference, emitted, words)
        for bad in [emitted.replace('usr$p)', 'usr$q)'),
                    emitted.replace(word_call, word_call + word_call),
                    emitted.replace(word_call, word_call + 'mstore(0, 0)')]:
            with self.assertRaises(AssertionError):
                validate_source(reference, bad, words)
        with self.assertRaises(AssertionError):
            validate_source(reference.replace('not(479)', 'not(478)'), emitted, words)
        with self.assertRaises(AssertionError):
            validate_source(reference, emitted)
        code = bytes.fromhex('6101c0604052') + block + words + bytes.fromhex('00fea00001')
        source_map = '0;0;0;0;0;0'
        validate_runtime(code, source_map, block, words)
        for op in (0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff):
            bad = bytearray(code)
            bad[6 + len(block) + len(words)] = op
            with self.assertRaises(AssertionError):
                validate_runtime(bad, source_map, block, words)
        for bad in [code[:6] + words + code[6:], code[:-4] + b'\x5b' + code[-3:]]:
            with self.assertRaises(AssertionError):
                validate_runtime(bad, source_map, block, words)
        with self.assertRaises(AssertionError):
            validate_runtime(code, source_map, block)
        with self.assertRaises(AssertionError):
            validate_runtime(code, '0;0;0;0;0', block, words)


if __name__ == '__main__':
    unittest.main()
