require "omniauth-trustauth/version"
require 'omniauth-trustauth/railtie' if defined?(Rails)
require 'omniauth/strategies/trustauth'

OmniAuth.config.add_camelization('trustauth', 'TrustAuth')
