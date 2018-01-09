overrides = []

require_controls 'disa_stig-el7-baseline' do
  # SIMP uses Rsyslog for log offloading
  # Need to create a profile and tests
  control 'V-72087' do
    overrides << self.to_s

    only_if { file('/etc/audisp/audisp-remote.conf').exist? }
  end

  @conf['profile'].info[:controls].each do |ctrl|
    next if overrides.include?(ctrl[:id])

    tags = ctrl[:tags]
    if tags && tags[:subsystems]
      if tags[:subsystems].include?('audit')
        control ctrl[:id]
      end
    end
  end
end
