Vendored from calagopus/tundra commit ccb05e1 (MIT).

Wings embeds the node as a child process for its Incus backend. Local changes add an Incus REST runtime adapter; the wire protocol, ACLs, namespace binder, and tunnel implementation remain upstream. Docker provisioning in Wings continues to use the configured external Tundra images.
