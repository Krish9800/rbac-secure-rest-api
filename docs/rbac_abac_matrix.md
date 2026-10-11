# RBAC & ABAC Entitlement Matrix

## 1. System Roles Hierarchy

```
SuperAdmin (Inherits ALL permissions across all resources)
  └── Admin (Administrative operations across users, roles, reports, system config, audit)
        ├── Auditor (Read-only access to audit logs, reports, and users)
        ├── Analyst (Create & read permissions on reports, analytical tasks)
        └── Viewer (Read-only access to reports)
```

---

## 2. Granular Permissions Mapping

| Resource | Action | SuperAdmin | Admin | Auditor | Analyst | Viewer |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **USERS** | `CREATE` | ✓ | ✓ | ✗ | ✗ | ✗ |
| **USERS** | `READ` | ✓ | ✓ | ✓ | ✗ | ✗ |
| **USERS** | `UPDATE` | ✓ | ✓ | ✗ | ✗ | ✗ |
| **USERS** | `DELETE` | ✓ | ✓ | ✗ | ✗ | ✗ |
| **ROLES** | `READ` | ✓ | ✓ | ✗ | ✗ | ✗ |
| **ROLES** | `MANAGE` | ✓ | ✓ | ✗ | ✗ | ✗ |
| **REPORTS** | `CREATE` | ✓ | ✓ | ✗ | ✓ | ✗ |
| **REPORTS** | `READ` | ✓ | ✓ | ✓ | ✓ | ✓ |
| **REPORTS** | `UPDATE` | ✓ | ✓ | ✗ | ✗ | ✗ |
| **REPORTS** | `DELETE` | ✓ | ✓ | ✗ | ✗ | ✗ |
| **AUDIT_LOGS** | `READ` | ✓ | ✓ | ✓ | ✗ | ✗ |
| **AUDIT_LOGS** | `EXPORT` | ✓ | ✓ | ✓ | ✗ | ✗ |
| **SYSTEM_CONFIG**| `MANAGE` | ✓ | ✓ | ✗ | ✗ | ✗ |

---

## 3. Contextual ABAC Attributes

| Attribute Name | Evaluation Rule | Security Defense Purpose |
|---|---|---|
| `resource_owner_id` | Must match requesting `user.user_id` (unless SuperAdmin) | Broken Object Level Authorization (BOLA / IDOR) Defense |
| `resource_tenant_id` | Must match requesting `user.tenant_id` (unless SuperAdmin) | Multi-tenant isolation / Cross-tenant data bleed prevention |
| `client_ip` | Validated against permitted CIDR network blocks | Restricting administrative endpoints to internal/VPN ranges |
| `request_time` | Validated against permissible hour range `[start, end)` | Temporal restrictions on highly sensitive operational hours |
| `mfa_authenticated` | Evaluates if step-up MFA verification was completed | Preventing critical changes with stolen access credentials |
