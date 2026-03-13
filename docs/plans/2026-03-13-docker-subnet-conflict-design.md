# Docker Subnet Conflict Design

**Context**

`boq` persists the managed Docker network subnet in `~/.boq/.docker-subnet`. If that subnet later becomes occupied by another bridge, `boq` will still reuse it and can create containers without usable outbound networking.

**Approaches**

1. Revalidate the persisted subnet before reuse and reallocate when it now overlaps an occupied network.
   Recommended because it fixes the observed root cause without changing the public model or CLI.
2. Stop persisting the Docker subnet and always recalculate it.
   Simpler logic, but it can break existing `boq-docker-net` setups and surprise users.
3. Add explicit Podman-only detection and special-case its default subnet.
   Too narrow. The real problem is stale persisted subnets, not Podman specifically.

**Design**

- Keep `boq-docker-net` as the managed Docker network.
- Treat the existing managed Docker network, when present, as the source of truth.
- When the managed Docker network does not exist, only reuse `~/.boq/.docker-subnet` if it does not overlap currently occupied networks.
- If the persisted subnet is now occupied, allocate a fresh subnet from the existing Docker candidate range and overwrite `~/.boq/.docker-subnet`.

**Testing**

- Add a regression test showing a persisted `10.88.0.0/16` subnet is replaced when current occupied networks include `10.88.0.0/16`.
- Add a guard test showing an existing `boq-docker-net` still wins even if its subnet appears occupied from the host perspective.
