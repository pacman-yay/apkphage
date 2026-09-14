from lxml import etree

# Permissions that, individually, aren't damning - but in combination
# are a strong banking-trojan/dropper signal. Based on patterns observed
# across both samples analyzed manually (Rashan Card + RTO Challan).
HIGH_RISK_COMBOS = [
    {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.QUERY_ALL_PACKAGES"},
    {"android.permission.BIND_VPN_SERVICE"},
    {"android.permission.BIND_ACCESSIBILITY_SERVICE"},
    {
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    },
]

NAMESPACE = {"android": "http://schemas.android.com/apk/res/android"}


def parse_manifest(manifest_path: str) -> dict:
    tree = etree.parse(manifest_path)
    root = tree.getroot()

    permissions = set()
    for perm in root.findall(".//uses-permission"):
        name = perm.get("{http://schemas.android.com/apk/res/android}name")
        if name:
            permissions.add(name)

    package = root.get("package", "unknown")

    # Flag components with suspicious naming (Loader, Bridge, Core, etc.)
    # or exported=true combined with intent-filters for BOOT_COMPLETED.
    # Also harvest android:permission attrs declared directly on service/
    # receiver/activity elements - they grant permission-level access that
    # <uses-permission> tags don't surface, and matter for combo checks.
    suspicious_components = []
    declared_component_permissions = set()
    for tag in ["activity", "service", "receiver"]:
        for comp in root.findall(f".//{tag}"):
            name = comp.get("{http://schemas.android.com/apk/res/android}name", "")
            exported = comp.get("{http://schemas.android.com/apk/res/android}exported", "false")
            perm = comp.get("{http://schemas.android.com/apk/res/android}permission")
            if perm:
                declared_component_permissions.add(perm)
            actions = [
                a.get("{http://schemas.android.com/apk/res/android}name")
                for a in comp.findall(".//action")
            ]
            flag_reasons = []
            if any(k in name for k in ["Loader", "Bridge", "Core", "Drop"]):
                flag_reasons.append("suspicious_naming")
            if "android.intent.action.BOOT_COMPLETED" in actions:
                flag_reasons.append("boot_persistence")
            if exported == "true" and tag == "receiver":
                flag_reasons.append("exported_receiver")

            if flag_reasons:
                suspicious_components.append(
                    {
                        "type": tag,
                        "name": name,
                        "reasons": flag_reasons,
                    }
                )

    # Check high-risk combos against uses-permission AND component-declared
    # permissions combined - BIND_ style guard perms often appear only as
    # android:permission attrs on a service/receiver, never in uses-permission.
    combined_permissions = permissions | declared_component_permissions
    matched_combos = [combo for combo in HIGH_RISK_COMBOS if combo.issubset(combined_permissions)]

    # queries/meta-data referencing another package name = possible
    # dropper relationship (matches the jcr.opyvkpx.leejw pattern we found)
    referenced_packages = []
    for q in root.findall(".//queries/package"):
        pkg = q.get("{http://schemas.android.com/apk/res/android}name")
        if pkg:
            referenced_packages.append(pkg)

    return {
        "package": package,
        "permissions": sorted(permissions),
        "declared_component_permissions": sorted(declared_component_permissions),
        "high_risk_permission_combos": [sorted(c) for c in matched_combos],
        "suspicious_components": suspicious_components,
        "referenced_external_packages": referenced_packages,
    }
