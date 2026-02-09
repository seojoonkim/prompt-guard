# Prompt Guard v3.1.0 — Token Optimization Release

> **550+ 공격 패턴 · 11 SHIELD 카테고리 · 10개 언어 지원**
> 
> 보안 성능 100% 유지하면서 토큰 소모량 최대 90% 절감

---

## 🛡️ 현재 Prompt Guard의 보안 규모

| 지표 | 수치 | 의미 |
|------|------|------|
| **총 공격 패턴** | 550+ | 직접 주입부터 MCP 악용까지 |
| **SHIELD 카테고리** | 11개 | prompt, tool, mcp, memory, supply_chain 등 |
| **지원 언어** | 10개 | EN, KO, JA, ZH, RU, ES, DE, FR, PT, VI |
| **인코딩 탐지** | 6종 | Base64, Hex, ROT13, URL, HTML, Unicode |
| **테스트 커버리지** | 115개 | 모든 기능 회귀 테스트 |

**v1.0 (50개 패턴) → v3.1 (550+ 패턴): 11배 성장**

---

## ⚡ v3.1.0의 핵심: 왜 토큰 최적화인가?

### 문제 인식

AI 에이전트의 컨텍스트 윈도우는 유한합니다. SKILL.md가 크면:
- 🔴 대화 길이 제한 (컨텍스트 소진)
- 🔴 응답 지연 (토큰 처리 시간)
- 🔴 비용 증가 (토큰당 과금)

기존 Prompt Guard는 744줄의 SKILL.md로 **매 세션 ~5-6k 토큰**을 소비했습니다.

### 해결 방법

**"보안은 그대로, 토큰만 줄이자"**

| 최적화 | 절감률 | 원리 |
|--------|--------|------|
| SKILL.md 경량화 | 65% | 문서 분리, Quick Start만 유지 |
| 티어드 패턴 로딩 | 70% | 필요한 패턴만 점진적 로드 |
| 메시지 해시 캐시 | 90% | 중복 분석 제거 |

---

## 🆕 v3.1.0 새 기능 상세

### 1. 티어드 패턴 로딩 (Tiered Pattern Loading)

**컨셉:** 모든 위협이 동등하지 않다. 진짜 위험한 건 항상 체크하고, 나머지는 필요할 때만.

| Tier | 패턴 | 언제? | 예시 |
|------|------|-------|------|
| **Tier 0** | CRITICAL ~30개 | 항상 | API키 탈취, `rm -rf`, SQL injection |
| **Tier 1** | HIGH ~70개 | 기본 | 인스트럭션 오버라이드, 탈옥 시도 |
| **Tier 2** | MEDIUM ~100개 | 위협 시 | 역할 조작, 감정 조작 |

**보안 유지 원리:**
```
일반 메시지 → Tier 0+1 스캔 (100개) → 안전 → 통과
의심 메시지 → Tier 0+1 스캔 → 위협 감지 → Tier 2 확장 → 전체 550+ 스캔
```

위협이 감지되면 즉시 전체 패턴으로 확장합니다. **안전할 땐 빠르게, 위험할 땐 철저하게.**

### 2. 메시지 해시 캐시 (Message Hash Cache)

**컨셉:** 같은 메시지는 같은 결과. 두 번 분석할 필요 없다.

| 설정 | 값 |
|------|-----|
| 캐시 크기 | LRU 1,000개 |
| 해시 알고리즘 | SHA-256 |
| 스레드 안전 | ✅ |

**보안 유지 원리:**
- 메시지 원문 저장 안 함 (해시만)
- 동일 입력 = 동일 출력 (결정적 함수)
- 새 메시지는 항상 전체 분석

### 3. 패턴 외부화 (External Pattern Files)

**컨셉:** SKILL.md에서 패턴을 분리하여 컨텍스트 토큰 절약.

```
patterns/
├── critical.yaml   # Tier 0 (~30개)
├── high.yaml       # Tier 1 (~70개)
└── medium.yaml     # Tier 2 (~100개)
```

패턴은 Python 런타임에서 YAML로 로드됩니다. **탐지 로직은 동일, 컨텍스트 부담만 감소.**

---

## 📊 실제 절감 효과

### 일반 대화 (대부분의 경우)
```
이전: 744줄 SKILL.md 로드 → ~5-6k 토큰
이후: 261줄 SKILL.md 로드 → ~1.5-2k 토큰
절감: 65-70%
```

### 반복 메시지 (인사, 자주 쓰는 표현)
```
이전: 매번 전체 분석
이후: 캐시 히트 → 즉시 반환
절감: 90%+
```

### 위협 탐지 시
```
Tier 확장 → 전체 550+ 패턴 로드
보안 성능: 100% 유지
```

---

## 📜 최근 10개 릴리즈 히스토리

### v3.1.0 (2026-02-09) — 이번 릴리즈 ⭐
토큰 최적화: 티어드 로딩, 해시 캐시, SKILL.md 경량화

### v3.0.1 (2026-02-08)
HiveFence Scout Round 3: Sockpuppetting, TrojanPraise, Promptware Kill Chain

### v3.0.0 (2026-02-07) — 메이저 릴리즈
패키지 리팩토링: `scripts/detect.py` → `prompt_guard/` 모듈화

### v2.8.2 (2026-02-07)
토큰 스플리팅 방어 100% 커버리지, 한국어 데이터 탈취 패턴 11개 추가

### v2.8.1 (2026-02-07)
Enterprise DLP: `sanitize_output()` 자격증명 자동 수정, 17개 크리덴셜 포맷

### v2.8.0 (2026-02-07)
Phase 1 하드닝: 6종 인코딩 디코드, 출력 DLP, 카나리 토큰, 76개 테스트

### v2.7.0 (2026-02-05)
HiveFence Scout: MCP 악용, 유니코드 태그, 브라우저 에이전트 공격 등 6개 카테고리

### v2.6.2 (2026-02-05)
10개 언어 확장: 러시아어, 스페인어, 독일어, 프랑스어, 포르투갈어, 베트남어

### v2.6.1 (2026-02-05)
HiveFence Scout: Allowlist 우회, Hooks 하이재킹, 서브에이전트 악용 등 5개 카테고리

### v2.6.0 (2026-02-01)
실전 레드팀 대응: 단일 승인 확장, 크리덴셜 경로 하베스팅, DM 소셜 엔지니어링

---

## 🔢 버전별 성장 추이

| 버전 | 패턴 수 | 주요 추가 |
|------|---------|----------|
| v1.0 | 50+ | 기본 프롬프트 주입 방어 |
| v2.0 | 130+ | 다국어, 심각도 점수 |
| v2.5 | 349 | 7개 신규 카테고리 |
| v2.6 | 400+ | 10개 언어, 소셜 엔지니어링 |
| v2.7 | 460+ | MCP/브라우저 에이전트 |
| v2.8 | 500+ | 인코딩 우회, DLP |
| v3.0 | 520+ | 패키지 리팩토링, SHIELD.md |
| **v3.1** | **550+** | **토큰 최적화** |

---

## 🚀 시작하기

### 설치
```bash
pip install prompt-guard
# 또는
clawdhub install prompt-guard
```

### 사용
```python
from prompt_guard import PromptGuard

guard = PromptGuard()
result = guard.analyze("user message")

if result.action == "block":
    return "🚫 차단됨"
```

### 설정 (선택)
```yaml
prompt_guard:
  pattern_tier: high   # critical, high, full
  cache:
    enabled: true
    max_size: 1000
```

---

## 🏗️ 프로젝트 구조

```
prompt-guard/
│
├── 📦 prompt_guard/              # 핵심 Python 패키지
│   ├── __init__.py               # 모듈 export
│   ├── engine.py                 # PromptGuard 메인 클래스
│   ├── patterns.py               # 550+ 정규식 패턴 정의
│   ├── pattern_loader.py         # 🆕 티어드 로딩 시스템
│   ├── cache.py                  # 🆕 LRU 해시 캐시
│   ├── scanner.py                # 패턴 매칭 엔진
│   ├── normalizer.py             # 텍스트 정규화 (호모글리프 등)
│   ├── decoder.py                # 인코딩 탐지/디코드
│   ├── output.py                 # 출력 DLP (자격증명 수정)
│   ├── models.py                 # Severity, Action, DetectionResult
│   ├── hivefence.py              # HiveFence 네트워크 연동
│   ├── logging_utils.py          # SIEM 호환 JSON 로깅
│   └── cli.py                    # CLI 진입점
│
├── 📁 patterns/                  # 🆕 외부 패턴 파일 (YAML)
│   ├── critical.yaml             # Tier 0: ~30개 (항상 로드)
│   ├── high.yaml                 # Tier 1: ~70개 (기본 로드)
│   └── medium.yaml               # Tier 2: ~100개 (동적 확장)
│
├── 🧪 tests/                     # 테스트 스위트
│   └── test_detect.py            # 115개 회귀 테스트
│
├── 📄 SKILL.md                   # 스킬 정의 (경량화됨: 261줄)
├── 📄 CHANGELOG.md               # 전체 버전 히스토리
├── 📄 RELEASE-v3.1.0.md          # 이 문서
└── 📄 LICENSE                    # MIT 라이센스
```

### 모듈별 역할

| 모듈 | 역할 | 라인 수 |
|------|------|---------|
| `engine.py` | 전체 분석 오케스트레이션, 설정 관리, Rate Limit | ~400 |
| `patterns.py` | 550+ 정규식 패턴 (순수 데이터) | ~1,200 |
| `pattern_loader.py` | 티어드 로딩, YAML 파싱, 동적 확장 | ~230 |
| `cache.py` | LRU 캐시, SHA-256 해싱, 스레드 안전 | ~180 |
| `scanner.py` | 정규식 매칭, 다중 패턴 병렬 스캔 | ~100 |
| `normalizer.py` | 호모글리프 변환, 유니코드 정규화 | ~200 |
| `decoder.py` | Base64/Hex/ROT13/URL/HTML/Unicode 디코드 | ~200 |
| `output.py` | 출력 DLP, 자격증명 자동 수정 | ~210 |

### 데이터 흐름

```
사용자 메시지
     ↓
┌─────────────────────────────────────────────────────────┐
│  1. 캐시 조회 (cache.py)                                │
│     └─ 히트? → 즉시 반환 (90% 절감)                     │
└─────────────────────────────────────────────────────────┘
     ↓ 미스
┌─────────────────────────────────────────────────────────┐
│  2. 전처리 (normalizer.py + decoder.py)                 │
│     └─ 호모글리프 변환, 인코딩 디코드                   │
└─────────────────────────────────────────────────────────┘
     ↓
┌─────────────────────────────────────────────────────────┐
│  3. 티어드 스캔 (pattern_loader.py + scanner.py)        │
│     └─ Tier 0+1 스캔 → 위협? → Tier 2 확장             │
└─────────────────────────────────────────────────────────┘
     ↓
┌─────────────────────────────────────────────────────────┐
│  4. 결과 생성 (engine.py)                               │
│     └─ Severity, Action, SHIELD 카테고리 결정           │
└─────────────────────────────────────────────────────────┘
     ↓
┌─────────────────────────────────────────────────────────┐
│  5. 캐시 저장 + 로깅 (cache.py + logging_utils.py)      │
│     └─ 결과 캐시, SIEM 로그                             │
└─────────────────────────────────────────────────────────┘
     ↓
  DetectionResult 반환
```

---

## 📜 MIT 라이센스 — 왜 오픈소스인가?

### MIT 라이센스란?

```
MIT License

Copyright (c) 2026 Seojoon Kim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

**가장 자유로운 오픈소스 라이센스 중 하나입니다.**

### 당신이 할 수 있는 것

| 권리 | 설명 |
|------|------|
| ✅ **상업적 사용** | 회사 제품에 통합 가능 |
| ✅ **수정** | 코드를 자유롭게 수정 |
| ✅ **배포** | 수정본 재배포 가능 |
| ✅ **사적 사용** | 개인 프로젝트에 사용 |
| ✅ **서브라이센스** | 다른 라이센스로 재배포 가능 |

### 유일한 조건

- **저작권 표시 유지**: 라이센스 파일과 저작권 표시를 포함해야 합니다.
- 그게 끝입니다.

### 왜 MIT를 선택했나?

**AI 에이전트 보안은 모두의 문제입니다.**

1. **접근성**: 누구나 무료로 사용 가능
2. **투명성**: 코드를 직접 검증 가능
3. **확산**: 더 많은 에이전트가 보호받을수록 생태계가 안전해짐
4. **신뢰**: 블랙박스가 아닌 오픈 알고리즘

### HiveFence와의 시너지

```
개인이 공격 발견 → prompt-guard로 탐지 → HiveFence에 보고 → 전체 네트워크 면역
```

**오픈소스 + 집단지성 = 모두를 위한 보안**

---

## 📎 링크

- **GitHub:** [seojoonkim/prompt-guard](https://github.com/seojoonkim/prompt-guard)
- **ClawdHub:** [clawdhub.com/skills/prompt-guard](https://clawdhub.com/skills/prompt-guard)
- **HiveFence:** [hivefence.com](https://hivefence.com)

---

**Author:** Seojoon Kim  
**License:** MIT  
**Date:** 2026-02-09
