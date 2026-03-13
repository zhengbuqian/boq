# Docker Subnet Conflict Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `boq` stop reusing a persisted Docker subnet when that subnet now conflicts with an occupied host network.

**Architecture:** Keep the current Docker managed network model. Change subnet selection so the existing `boq-docker-net` remains authoritative, but a stale persisted subnet is revalidated against current occupied networks before reuse.

**Tech Stack:** Python 3.11, `unittest`, existing `boq.core.Boq` runtime helpers

---

### Task 1: Add a regression test for stale persisted Docker subnets

**Files:**
- Create: `tests/test_docker_subnet.py`
- Modify: `src/boq/core.py`

**Step 1: Write the failing test**

Create a test that:
- writes `10.88.0.0/16` into `~/.boq/.docker-subnet`
- simulates no existing `boq-docker-net`
- simulates current occupied networks including `10.88.0.0/16`
- expects `_get_or_allocate_docker_subnet_locked()` to return `10.200.0.0/16`

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_docker_subnet -v`
Expected: failure because stored Docker subnets are reused without revalidation.

**Step 3: Write minimal implementation**

Update Docker subnet allocation so:
- existing `boq-docker-net` remains authoritative
- persisted subnet is only reused when it does not overlap current occupied networks

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_docker_subnet -v`
Expected: PASS

### Task 2: Add a guard test for existing managed Docker networks

**Files:**
- Modify: `tests/test_docker_subnet.py`
- Modify: `src/boq/core.py`

**Step 1: Write the failing test**

Add a test that simulates an existing `boq-docker-net` already using `10.200.0.0/16` and expects that subnet to be returned directly.

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_docker_subnet -v`
Expected: failure if the implementation incorrectly rejects the current managed network.

**Step 3: Write minimal implementation**

Preserve current behavior where an existing managed Docker network is adopted and persisted.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_docker_subnet -v`
Expected: PASS
