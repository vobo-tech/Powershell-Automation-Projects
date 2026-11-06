# Identity & Access Management

This folder groups PowerShell automation scripts related to user accounts, permissions, and Group Policy management in enterprise environments.

## Categories

### ADIdentityOps
A tested-against-a-synthetic-AD module for read-only identity snapshots, reviewable offboarding plans, controlled execution with `-WhatIf`, verification, resume, and JSON/CSV/HTML evidence. Not production-ready; see [ADIdentityOps/README.md](ADIdentityOps/README.md) for status, permissions, and limitations.

### UserAccountManagement
Scripts for creating, modifying, and managing user accounts including bulk operations, password resets, and inactive account reporting.

### PermissionAuditing
Tools for auditing and reporting on permissions including NTFS permissions and over-permissioned account detection.

### GroupPolicyManagement
Scripts for managing Group Policy Objects (GPOs) including conflict detection and applied GPO reporting.

## Purpose
These automation tools help IT administrators efficiently manage identity and access controls across Windows domains while maintaining security and compliance standards.