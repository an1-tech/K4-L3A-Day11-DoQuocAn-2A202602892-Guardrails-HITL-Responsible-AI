# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-26T09:25:21.878121+00:00`
- Framework: `google-adk`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/8`
- Attack queries blocked: `10/10`
- Edge cases blocked: `4/6`
- Rate limit blocked/sent: `5/15`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `gemini` / `gemini-3.5-flash`
- Unsafe leaks (Red): `4/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
..........                                                               [100%]
============================== warnings summary ===============================
.venv\Lib\site-packages\_pytest\cacheprovider.py:469
  D:\Thuc hanh AI\K4-L3A-Day11-DoQuocAn-2A202602892-Guardrails-HITL-Responsible-AI\.venv\Lib\site-packages\_pytest\cacheprovider.py:469: PytestCacheWarning: could not create cache path D:\Thuc hanh AI\K4-L3A-Day11-DoQuocAn-2A202602892-Guardrails-HITL-Responsible-AI\.pytest_cache\v\cache\nodeids: [WinError 183] Cannot create a file when that file already exists: 'D:\\Thuc hanh AI\\K4-L3A-Day11-DoQuocAn-2A202602892-Guardrails-HITL-Responsible-AI\\.pytest_cache\\v\\cache'
    config.cache.set("cache/nodeids", sorted(self.cached_nodeids))

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
10 passed, 1 warning in 1.27s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
