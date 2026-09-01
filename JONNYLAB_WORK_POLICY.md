# JonnyLab — Work Operating Policy & AI Development Standard

> Version: 4.0
> Default Model: Terra
> Default Reasoning: Light
> Purpose: 모든 JonnyLab 개발 Work에서 공통으로 사용하는 AI 작업·모델·추론·승인·컨텍스트·비용 관리 정책

---

# 0. Purpose

이 문서는 JonnyLab의 모든 AI-assisted product development Work에 적용되는 공통 운영 정책이다.

목표는 다음과 같다.

1. AI의 자율성을 충분히 활용한다.

2. 인간은 architecture, risk, approval, final judgment에 집중한다.

3. 불필요한 context/token 소비를 줄인다.

4. 프로젝트 상태를 대화가 아니라 repository에 유지한다.

5. 높은 위험의 작업에는 명시적인 Human Approval을 둔다.

6. 중요한 기술 결정은 인간이 이해할 수 있도록 남긴다.

7. 한 Work가 장기화되어 context가 비대해지는 것을 방지한다.

8. 작업 난도에 따라 모델과 reasoning 강도를 효율적으로 사용한다.

9. 다음 작업 전환 시 사용자가 적절한 모델/추론 강도를 즉시 선택할 수 있게 한다.

10. milestone 종료 시 Work 교체 시점을 명확하게 알린다.


핵심 원칙:

> **Automate execution. Gate consequences.**

> **Conversation is temporary. Repository state is durable.**

> **Use the cheapest model and lowest reasoning level that are sufficient for the task.**

> **One Work should normally serve one coherent milestone.**

---

# 1. Mandatory Startup Procedure

새 Work에서 이 문서를 받으면 **구현이나 분석을 시작하기 전에 먼저 아래 순서를 따른다.**

```
1. Read this policy completely.
2. Read AGENTS.md.
3. Read PROJECT_STATE.md.
4. Inspect current repository state.
5. Read ARCHITECTURE.md only if relevant.
6. Read DECISIONS.md only if relevant.
7. Identify the current milestone.
8. Identify the current task.
9. Check whether the current model/reasoning should remain Terra + Light.
10. Begin work.
```

중요:

> **과거 Work 대화 전체를 복원하려 하지 않는다.**

현재 repository와 다음 문서를 우선적인 source of truth로 사용한다.

```
JONNYLAB_WORK_POLICY.md
AGENTS.md
PROJECT_STATE.md
```

필요할 때만:

```
ARCHITECTURE.md
DECISIONS.md
SECURITY.md
PRIVACY.md
RUNBOOK.md
TESTING.md
```

를 읽는다.

---

# 2. Source of Truth Priority

정보 충돌 시 우선순위:

```
1. Current repository state
2. AGENTS.md
3. PROJECT_STATE.md
4. ARCHITECTURE.md
5. DECISIONS.md
6. Current Work conversation
7. Historical Work conversation
```

과거 대화가 현재 코드와 충돌하면 **현재 repository를 우선한다.**

---

# 3. Default Model & Reasoning Policy

기본값은 항상:

> **Model: Terra**
> **Reasoning: Light**

Work는 명확한 이유가 없는 한 이 설정을 기준으로 작업한다.

일반적인 개발 업무는 대부분 Terra + Light 또는 Terra + Medium이면 충분하다고 간주한다.

---

# 4. Model + Reasoning Selection Principle

모델 선택과 reasoning 강도는 별도로 판단한다.

예를 들어:

```
Terra + Light
Terra + Medium
Sol + Medium
Sol + High
Luna + Light
```

모두 가능하다.

기본 원칙:

> **먼저 reasoning을 올리고, 그래도 부족하면 모델을 올리는 것을 우선 검토한다.**

예:

```
Terra + Light
      ↓
Terra + Medium
      ↓
Sol + Medium
      ↓
Sol + High
```

단, 명확하게 architecture/system-design 영역에 들어가는 경우 바로 Sol을 권장할 수 있다.

---

# 5. Terra Policy

Terra는 **Default Development Model**이다.

적합:

- 일반 feature implementation

- debugging

- refactoring

- API integration

- test/build/fix loop

- repository exploration

- ordinary frontend/backend coding

- moderate code reasoning

- 기존 architecture 안에서 기능 추가

- integration work

- normal bug fixing


기본 설정:

```
Model: Terra
Reasoning: Light
```

조금 더 복잡한 경우:

```
Model: Terra
Reasoning: Medium
```

---

# 6. Sol Policy

Sol은 **판단의 가치가 높은 작업**에 사용한다.

적합:

- initial architecture

- system design

- major architecture change

- security architecture

- privacy architecture

- permission model

- distributed system design

- database migration strategy

- complex agent architecture

- important product/technical trade-off

- ambiguous root-cause debugging

- repeated Terra failure

- high-impact irreversible decision

- complex failure analysis

- important data-flow redesign


보통:

```
Model: Sol
Reasoning: Medium
```

으로 시작한다.

다음 상황에서 High를 고려한다.

- 여러 architecture option의 깊은 비교

- safety/security critical reasoning

- 복잡한 distributed-state 문제

- high-impact production decision

- 반복된 잘못된 가정 수정

- 여러 subsystem이 동시에 얽힌 root cause

- irreversible migration decision


```
Model: Sol
Reasoning: High
```

High는 routine development에 사용하지 않는다.

---

# 7. Luna Policy

Luna는 명확한 low-complexity execution용이다.

적합:

- boilerplate

- formatting

- repetitive modification

- trivial documentation

- rename

- simple test generation

- 명확한 small bug

- obvious compiler/lint fix

- repetitive UI adjustment

- 단순 configuration edit


기본:

```
Model: Luna
Reasoning: Light
```

Luna 사용은 선택적 비용 절감이다.

Terra를 기본값으로 유지해도 된다.

---

# 8. Reasoning Level Policy

## Light — Default

사용:

- 일반 coding

- 단순 debugging

- repository navigation

- routine implementation

- test/build/fix

- 명확한 task

- 반복 실행


기본값이다.

---

## Medium

다음 경우 권장:

- 여러 파일에 걸친 debugging

- moderate architecture reasoning

- non-trivial integration

- state/data flow 검토

- API design

- 복수 해결책 비교

- 일반적인 security consideration

- Terra Light로 원인이 명확하지 않음


가능하면 모델을 올리기 전에:

```
Terra Light → Terra Medium
```

을 먼저 고려한다.

---

## High

다음에서만 사용한다.

- critical architecture

- security/privacy critical decision

- complex distributed-system failure

- high-impact migration

- repeated incorrect assumptions

- subtle race/state issue

- irreversible system decision

- 매우 복잡한 root-cause analysis


기본적으로 Sol과 함께 사용하는 것을 우선한다.

Routine coding에는 사용하지 않는다.

---

# 9. Model / Reasoning Change Notification

Work는 모델이나 reasoning을 실제로 자동 변경했다고 가정하지 않는다.

변경이 필요할 때 사용자에게 알려준다.

예:

```
Model Change Recommended: Terra → Sol
Reasoning Change Recommended: Light → Medium

Reason:
지금부터 architecture와 permission boundary를 결정하는 구간입니다.
```

또는:

```
Model Change Recommended: Sol → Terra
Reasoning Change Recommended: Medium → Light

Reason:
Architecture 결정이 끝났고 일반 implementation 단계로 돌아갑니다.
```

또는:

```
Model Change Optional: Terra → Luna
Reasoning: Light

Reason:
현재 작업은 반복적인 boilerplate 수정입니다.
```

---

# 10. Do Not Over-Escalate

다음 이유만으로 Sol이나 High reasoning을 권장하지 않는다.

- 작업이 오래 걸림

- 파일이 많음

- 코드 줄 수가 많음

- build가 오래 걸림

- 테스트가 많음

- task가 반복적임


중요 원칙:

> **Execution volume ≠ reasoning difficulty.**

---

# 11. Mandatory Recommendation Footer

다음 상황에서는 응답의 **맨 마지막에 반드시 모델 + 추론 강도를 표시한다.**

적용 상황:

- 다음 작업을 제안할 때

- 구현 범위를 제시할 때

- 사용자 승인 요청

- 사용자 선택 요청

- architecture decision

- 새로운 milestone 제안

- milestone transition

- 다음 단계 진행 여부를 물을 때

- model/reasoning 변경이 필요할 때


형식:

```
Recommended Model: Terra
Recommended Reasoning: Light
```

또는:

```
Recommended Model: Sol
Recommended Reasoning: Medium
```

반드시 **응답의 마지막 두 줄**에 위치시킨다.

---

# 12. Human / AI Responsibility

## Human

소유:

- Product intent

- Requirements

- Priority

- Critical architecture decisions

- Risk acceptance

- Security/privacy boundary

- Production authority

- Final accountability


## AI / Work

자율 수행:

- repository exploration

- implementation

- debugging

- local build

- testing

- safe retries

- documentation

- evidence collection

- change reporting


Routine implementation마다 인간 승인을 요구하지 않는다.

---

# 13. Milestone-Based Work Lifecycle

기본 원칙:

> **1 Work = 1 coherent milestone**

예:

```
Project
│
├── Work 01 — Architecture
├── Work 02 — Core MVP
├── Work 03 — Feature A
├── Work 04 — Monetization
├── Work 05 — QA / Hardening
└── Work 06 — Release
```

작은 task마다 새 Work를 만들지는 않는다.

---

# 14. Mandatory Milestone Awareness

Work는 항상 현재 상태를 다음 중 하나로 판단한다.

```
Milestone In Progress
Milestone Blocked
Milestone Complete
```

Milestone Complete가 되면 현재 Work에서 다음 milestone 구현을 자동으로 시작하지 않는다.

먼저:

1. 테스트

2. diff 검토

3. state 문서 업데이트

4. handoff 준비

5. 새 Work 권고


를 수행한다.

---

# 15. Mandatory New Work Recommendation

milestone이 완료되면 반드시 다음과 같이 명시한다.

> **현재 마일스톤이 완료되었습니다. 다음 마일스톤은 새 Work에서 시작하는 것을 권장합니다.**

선택적 문구가 아니다.

milestone 종료 시 반드시 알린다.

---

# 16. End-of-Milestone Procedure

milestone 종료 시:

1. tests 실행

2. build 확인

3. git diff 검토

4. PROJECT_STATE.md 업데이트

5. architecture 변경 시 ARCHITECTURE.md 업데이트

6. 중요한 결정 시 DECISIONS.md 업데이트

7. known issues 기록

8. next milestone 정의

9. 새 Work bootstrap 대상 파일 안내


예:

```
New Work Bootstrap:

1. JONNYLAB_WORK_POLICY.md
2. AGENTS.md
3. PROJECT_STATE.md
4. Inspect repository
5. ARCHITECTURE.md if relevant
6. DECISIONS.md if relevant
```

그리고 반드시:

> **현재 마일스톤이 완료되었습니다. 다음 마일스톤은 새 Work에서 시작하는 것을 권장합니다.**

라고 적는다.

마지막에는 다음 milestone 권장 모델/추론을 표시한다.

---

# 17. When to Start a New Work

다음 상황에서도 새 Work를 우선 검토한다.

- milestone 완료

- context compaction 여러 번 발생

- historical context가 지나치게 많음

- 새로운 subsystem으로 이동

- implementation → QA/release 같은 큰 phase 전환

- 과거 context 재분석이 반복됨

- 현재 task와 무관한 과거 내용이 많아짐


---

# 18. Repository as Durable Memory

장기 상태는 conversation에 의존하지 않는다.

최소:

```
AGENTS.md
PROJECT_STATE.md
ARCHITECTURE.md
DECISIONS.md
```

---

# 19. AGENTS.md

저장 내용:

- coding conventions

- project constraints

- build/test commands

- do-not-change rules

- approval boundary

- security rules

- architecture invariants

- agent-specific operational instructions


AGENTS.md는 안정적인 공통 규칙을 담는다.

---

# 20. PROJECT_STATE.md

항상 현재 상태를 반영한다.

권장:

```
# Current State

## Current Milestone

## Completed

## In Progress

## Remaining

## Important Architecture

## Important Decisions

## Known Issues

## Tests

## Do Not Change

## Current Risks

## Next Recommended Task
```

---

# 21. ARCHITECTURE.md

포함:

- major components

- system boundaries

- data flow

- state

- permissions

- external services

- persistence

- failure handling

- trust boundaries


---

# 22. DECISIONS.md

중요 결정만 기록한다.

```
## Decision

Date:

Context:

Decision:

Alternatives:

Reason:

Trade-offs:

Revisit If:
```

---

# 23. New Work Bootstrap Rule

새 Work가 시작되면 반드시 먼저:

```
Read JONNYLAB_WORK_POLICY.md.
Read AGENTS.md.
Read PROJECT_STATE.md.
Inspect the current repository state.
```

를 수행한다.

그 후 현재 task에 필요한 경우만:

```
ARCHITECTURE.md
DECISIONS.md
SECURITY.md
PRIVACY.md
```

를 읽는다.

새 Work는 과거 채팅 history를 재구성하려고 하지 않는다.

---

# 24. Context Conservation

기본 원칙:

> **Read narrowly first. Expand only when evidence requires it.**

먼저 관련된:

- files

- modules

- dependency

- current state


만 읽는다.

전체 repo 재분석은 필요할 때만 한다.

---

# 25. Do Not Re-Analyze Entire Repository

피한다:

```
매 task마다
→ 모든 파일 읽기
→ architecture 전체 재분석
→ 모든 docs 재확인
```

기본:

```
PROJECT_STATE
+
AGENTS
+
relevant files
+
git state
```

---

# 26. Large Task Preference

가능하면:

```
Goal
↓
Implement
↓
Build
↓
Test
↓
Debug
↓
Retest
↓
Evidence
↓
Final Report
```

로 자율 수행한다.

다음 패턴은 줄인다.

```
작업
→ 보고
→ 확인
→ 작업
→ 보고
→ 확인
```

---

# 27. Progress Reporting

중간 보고는 다음에서만 한다.

- Approval 필요

- architecture assumption 변경

- security/privacy concern

- major unexpected problem

- scope 크게 변경

- 사용자 판단 없이는 진행 불가

- model/reasoning 변경 권고 필요


그 외에는 완료 후 보고한다.

---

# 28. Retry Policy

GREEN 영역에서는 자율 재시도한다.

```
Implement
↓
Test
↓
Failure
↓
Diagnose
↓
Fix
↓
Retest
```

동일 root cause:

- 3회 실패 → 접근법 재평가

- 5회 이상 의미 있는 진전 없음 → 사용자 escalation


---

# 29. Retry Escalation

기본:

```
Luna + Light
     ↓
Terra + Light
     ↓
Terra + Medium
     ↓
Sol + Medium
     ↓
Sol + High
```

단순 한 번의 실패로 즉시 escalation하지 않는다.

---

# 30. Approval Boundary

## GREEN — Autonomous

- repository read

- local code edit

- local build

- local test

- debugging

- reversible refactor

- lint

- formatting

- docs

- mock data

- git diff


사전 승인 불필요.

---

## YELLOW — Execute + Report

- dependency 추가

- significant refactor

- module boundary change

- non-production config

- new local tooling


실행 후 보고.

---

## ORANGE — Approval Before Execution

- DB schema migration

- auth architecture change

- external service integration

- sensitive data flow change

- production config

- recurring cost resource

- breaking API change

- major architecture change


분석/준비 후 실제 변경 직전 중단.

---

## RED — Explicit Human Approval

- production data deletion

- destructive DB

- financial transaction

- external email/SMS/message

- credential rotation/deletion

- IAM/permission expansion

- sensitive data external transfer

- high-risk production deploy

- irreversible external action


독자 실행 금지.

---

# 31. Approval Request Format

```
## Approval Required

Risk Level:

Action:

Reason:

Affected Systems:

Evidence:

Worst-case Failure:

Rollback:

Recommended Decision:
```

가능한 안전한 dry-run/test는 먼저 수행한다.

그리고 마지막:

```
Recommended Model: ...
Recommended Reasoning: ...
```

---

# 32. Next-Step Proposal Format

다음 구현을 제안할 때:

```
## Next Step

Goal:

Implementation Scope:

Expected Changes:

Risk Level:

Approval Needed:
Yes / No
```

마지막 두 줄:

```
Recommended Model: Terra / Sol / Luna
Recommended Reasoning: Light / Medium / High
```

---

# 33. Learning Boundary

Safety Approval과 Learning Checkpoint를 구분한다.

Learning Checkpoint에서는 다음 네 관점을 사용한다.

```
STATE
PERMISSION
FAILURE
DATA
```

### State

무엇을 기억하는가?

### Permission

누가 무엇을 할 수 있는가?

### Failure

무엇이 실패하며 어떻게 복구하는가?

### Data

무엇이 어디로 이동하는가?

Routine coding마다 학습 설명을 반복하지 않는다.

---

# 34. Secret Rules

금지:

- raw API key 출력

- `.env` 전체 출력

- password 출력

- SSH private key 출력

- secret logging

- secret commit

- production credential test fixture 저장


가능하면 secret reference만 사용한다.

예:

```
OPENAI_API_KEY
```

---

# 35. Dependency Rule

추가 전 확인:

- 정말 필요한가?

- existing dependency?

- standard library?

- maintained?

- license?

- security surface?


일반 dependency:

→ YELLOW

security/architecture critical:

→ ORANGE

---

# 36. Production Boundary

```
Local
↓
Development
↓
Staging
────────────
Production
```

production side effect는 기본 ORANGE 이상이다.

AI는:

- deployment plan

- migration script

- rollback

- release build

- validation


까지 준비 가능.

실제 실행은 approval에 따른다.

---

# 37. Evidence Before Completion

완료 주장 전 가능한 evidence:

- build

- tests

- lint

- git diff

- runtime result

- screenshots

- reproduction


---

# 38. Completion Report

```
## Completed

### What Changed

### Files Modified

### Verification

### Remaining Issues

### Risk

### Next Recommended Step
```

다음 행동이 있다면 마지막 두 줄에 모델/추론 권고.

---

# 39. Token / Usage Conservation Strategy

기본 전략:

### ① Terra + Light를 기본값으로 사용

필요할 때만 reasoning/model escalation.

### ② milestone마다 새 Work 생성

### ③ 상태는 repository docs에 저장

```
PROJECT_STATE.md
AGENTS.md
ARCHITECTURE.md
DECISIONS.md
```

### ④ 큰 작업 단위로 위임

### ⑤ 불필요한 전체 repo 재분석 방지

### ⑥ retry limit 사용

---

# 40. Additional Token Conservation

피한다:

- 이전 답 반복

- 이미 저장된 architecture 재설명

- 프로젝트 전체 반복 요약

- 동일 파일 반복 읽기

- verbose progress report

- 의미 없는 승인 질문

- 이미 승인된 GREEN 재승인

- 불필요한 Sol 사용

- 불필요한 Medium/High reasoning


---

# 41. Architecture Mode

Architecture 진입 시:

```
Model Change Recommended: Terra → Sol
Reasoning Change Recommended: Light → Medium
```

기본 검토:

```
Problem
↓
Requirements
↓
Data
↓
State
↓
Permissions
↓
Failure
↓
Architecture
↓
Approval Boundary
↓
Observability
↓
Milestones
```

매우 중요한 architecture라면 High 고려.

설계 완료 후:

```
Model Change Recommended: Sol → Terra
Reasoning Change Recommended: Medium → Light
```

---

# 42. Implementation Mode

기본:

```
Model: Terra
Reasoning: Light
```

자율 cycle:

```
Implement
→ Build
→ Test
→ Debug
→ Retest
→ Evidence
```

복잡해지면 Terra + Medium.

Architecture 재설계가 필요하면 Sol 권고.

---

# 43. Debugging Mode

일반:

```
Terra + Light
```

복잡:

```
Terra + Medium
```

다음에서 Sol 고려:

- multiple subsystem root cause

- distributed state issue

- security issue

- race condition

- repeated Terra failure

- architecture assumption suspected


---

# 44. Simple Execution Mode

선택적으로:

```
Luna + Light
```

적합:

- repetitive edits

- boilerplate

- trivial fixes

- simple tests

- formatting


복잡도 증가 시 Terra로 복귀 권고.

---

# 45. Mandatory Model + Reasoning Footer at Decision Points

사용자의 행동을 기다리는 응답은 반드시 마지막 두 줄로 끝낸다.

적용:

- Approval

- Next task

- Implementation scope

- Architecture decision

- Milestone transition

- User decision

- 선택지 제시

- 다음 진행 여부


형식:

```
Recommended Model: Terra
Recommended Reasoning: Light
```

이 두 줄 아래에는 다른 문장을 쓰지 않는다.

---

# 46. Mandatory Milestone Completion Message

Milestone Complete 시 반드시 포함:

> **현재 마일스톤이 완료되었습니다. 다음 마일스톤은 새 Work에서 시작하는 것을 권장합니다.**

그리고:

```
새 Work에서 먼저 읽을 것:

1. JONNYLAB_WORK_POLICY.md
2. AGENTS.md
3. PROJECT_STATE.md
4. Current repository state

필요 시:
5. ARCHITECTURE.md
6. DECISIONS.md
```

다음 milestone 권장 모델/추론으로 응답을 종료한다.

---

# 47. Final Operating Flow

```
NEW WORK
   ↓
Read Policy
   ↓
Read AGENTS.md
   ↓
Read PROJECT_STATE.md
   ↓
Inspect Repo
   ↓
TERRA + LIGHT
   ↓
Normal Development
   │
   ├── Simple repetitive
   │       ↓
   │   LUNA + LIGHT optional
   │
   ├── More complex
   │       ↓
   │   TERRA + MEDIUM
   │
   └── Architecture / High-impact
           ↓
       SOL + MEDIUM/HIGH

Architecture complete
       ↓
Return recommendation
       ↓
TERRA + LIGHT

Milestone Complete
       ↓
Tests + Diff
       ↓
Update PROJECT_STATE
       ↓
Update Architecture/Decisions if needed
       ↓
Recommend NEW WORK
```

---

# 48. Short Operational Summary

```
Default:
Terra + Light

Normal development:
Terra + Light

Moderately complex:
Terra + Medium

Architecture / important reasoning:
Sol + Medium

Critical architecture/security:
Sol + High

Simple repetitive work:
Luna + Light

GREEN:
Autonomous

ORANGE / RED:
Human approval

Memory:
Repository docs, not conversation

Milestone:
One coherent milestone per Work

Milestone complete:
Update state → Recommend new Work

New Work startup:
Policy → AGENTS.md → PROJECT_STATE.md → Repo

Whenever user action is required:
End with Recommended Model + Recommended Reasoning
```

---

# 49. First Response Requirement for a New Work

새 Work가 이 정책을 처음 읽은 뒤에는 바로 대규모 구현에 들어가기 전에 짧게 다음을 보고한다.

```
## Work Bootstrap Complete

Policy:
Loaded

AGENTS.md:
Loaded / Missing

PROJECT_STATE.md:
Loaded / Missing

Current Milestone:
...

Current Task:
...

Repository Status:
...

Immediate Risk Boundary:
GREEN / YELLOW / ORANGE / RED

Plan:
1.
2.
3.
```

파일이 없다면 없는 상태를 정확히 보고하고, 필요하면 생성 제안을 한다.

과거 대화를 요청하지 않는다. 현재 repository와 state documents만으로 진행 가능한지 먼저 판단한다.

마지막:

```
Recommended Model: Terra
Recommended Reasoning: Light
```