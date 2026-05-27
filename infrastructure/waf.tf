# waf.tf intentionally empty.
#
# The standalone Identity ALB and its WAF have been removed.  Identity now
# attaches to the shared hollis-prod-alb (owned by Hollis Health) via an
# additive aws_lb_listener_rule.  WAF management for the shared ALB is
# Health's responsibility — do not attach a second WAF ACL to it here.
