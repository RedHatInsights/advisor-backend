# Developing Advisor Satellite Compatibility Layer
===========================================

## Local Satellite container for developer testing:

In order to run a local copy of satellite and run it against a local advisor api, follow these steps.

### Pre-reqs
1. Ensure ulimits are high. Add the following lines to `/etc/security/limits.conf`.  Restart your laptop.
    ```
    * soft nofile 100000
    * hard nofile 200000
    ```
1. Disable cgroups v2 (Fedora 32 and up)
    ```
    sudo grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"
    sudo grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
    ```
    Reboot
1. Install podman. `dnf install podman`  This will not work with docker.
1. Access to the insights dev cluster.  This is where the satellite container image is stored.

Start Satellite
--------------------

1. Log in with `oc` to the insights dev cluster
1. Log into the image registry. `podman login registry.insights-dev.openshift.com -u $(oc whoami) -p $(oc whoami -t)`
1. Run the satellite image `podman run -h advisor.satellite.test  --name satellite -d -p 8081:443 registry.insights-dev.openshift.com/advisor-ci/advisor-satellite-dev`
1. Log into https://localhost:8081 with login `admin/redhat` to ensure it is working

### Running against prod
By default, the satellite will point to classic prod. To switch this to advisor prod
1. `podman exec -it satellite bash -c "sed -i 's\https://cert-api.access.redhat.com\https://cert.console.redhat.com\' /etc/redhat_access/config.yml"`
1. `podman exec -it satellite systemctl restart httpd`

Often times it is useful to point to a branch_id that already has systems registered to it. This can be accomplished by:
* `podman exec -it satellite /bin/sh -i -c "sudo -u postgres psql -d candlepin -c \"update cp_upstream_consumer set uuid = '5db6a6f8-9f5b-4128-84b2-8b122cc9dbee'\""`

### Pointing satellite at your local api
1. `podman exec -it satellite bash -c "sed -i 's\https://cert-api.access.redhat.com\http://X.X.X.X:8000\' /etc/redhat_access/config.yml"`
 X.X.X.X is a local ip address of your laptop.  Do not use 127.0.0.1
1. Restart Satellite `podman exec -it satellite systemctl restart httpd`


### Running Advisor

1. When you run advisor ensure you bind to all network interfaces.
I.E. `manage.py runserver 0.0.0.0:8000`
1. Add `"*"` to `_DEFAULT_ALLOWED_HOSTS`
1. add `APPEND_SLASH = False` to settings.py to reduce 404s
1. Override Auth. Add the following to `permissions.py` at the top of `def authenticate(self, request):`

    `request.META[auth_header_key] = 'eyJpZGVudGl0eSI6IHsiYWNjb3VudF9udW1iZXIiOiAiNTQwMTU1IiwgInVzZXIiOnsiaXNfaW50ZXJuYWwiOnRydWUsInVzZXJuYW1lIjoicmhuLXN1cHBvcnQtZGt1YyJ9fX0='`
1. Navigate to `https://localhost:8081/redhat_access/insights/actions` to see requests come into the local api.

# A-B Testing

This tests the Classic interface ('A') against Advisor's Satellite-Compatibility
interface ('B').

We use the current Production interface for both Classic and Sat-compat
because clients can register easily through this interface, it's known to be
stable, and because the same data flows from Insights Core processing into
both Classic and Advisor.  There are other options - QA and CI environments -
but these are less stable or harder to get clients to register.

This procedure assumes you have credentials for account 540155.

We use Satellites in containers here.  If you have access to physical
Satellite installations, then run the commands on the Satellites directly
rather than using Podman.

### Start two satellite containers on different ports:
```bash
podman run -h advisor.satellite.test --name satellite_a -d -p 8082:443 registry.insights-dev.openshift.com/advisor-ci/advisor-satellite-dev
podman run -h advisor.satellite.test --name satellite_b -d -p 8083:443 registry.insights-dev.openshift.com/advisor-ci/advisor-satellite-dev
```
### Point them both to `5db6a6f8-9f5b-4128-84b2-8b122cc9dbee` branch id
```bash
podman exec -it satellite_a /bin/sh -i -c "sudo -u postgres psql -d candlepin -c \"update cp_upstream_consumer set uuid = '5db6a6f8-9f5b-4128-84b2-8b122cc9dbee'\""
podman exec -it satellite_b /bin/sh -i -c "sudo -u postgres psql -d candlepin -c \"update cp_upstream_consumer set uuid = '5db6a6f8-9f5b-4128-84b2-8b122cc9dbee'\""
```
This `branch_id` is used in account 540155 by an existing Satellite; we're
just piggy-backing on it.  If you're using a different account you may need
to find out the `branch_id` from the current Satellite, if it's used.  Either
way, both hosts must use the same `branch_id`.

### Change the second satellite to point to CRC and use basic auth
```bash
podman exec -it satellite_b bash -c "sed -i 's\https://cert-api.access.redhat.com\https://console.redhat.com\' /etc/redhat_access/config.yml"
podman exec -it satellite_b bash -c "sed -i 's\enable_telemetry_basic_auth : false\enable_telemetry_basic_auth : true\' /etc/redhat_access/config.yml"
podman exec -it satellite_b bash -c "sed -i 's\telemetry_ssl_verify_peer : true\telemetry_ssl_verify_peer : false\' /etc/redhat_access/config.yml"
podman exec -it satellite_b systemctl restart httpd
```
###  Configure basic auth
Log into Satellite B - `https://localhost:8083/redhat_access/insights/manage/`
- using the credentials `admin`/`redhat` and input your basic auth production
credentials in the 'Manage' section of the Insights menu.

### Log into each satellite
Open `https://localhost:8083/` and `https://localhost:8082` in separate browsers
(e.g. firefox/chrome, or two private browser windows). They use the same
cookie and will log each other out if opened in the same browser.
