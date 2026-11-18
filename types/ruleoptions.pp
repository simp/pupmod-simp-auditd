# @summary Options for one entry of `auditd::rules`
#
# The keys are the parameters of `auditd::rule`. `content` is required unless
# `ensure` is `absent`. New options are added here as Optional keys, so
# existing data keeps validating.
type Auditd::RuleOptions = Struct[{
    Optional['ensure']   => Enum['present', 'absent'],
    Optional['content']  => Variant[Array[String[1]], String[1]],
    Optional['order']    => String[1],
    Optional['first']    => Boolean,
    Optional['absolute'] => Boolean,
    Optional['prepend']  => Boolean,
}]
