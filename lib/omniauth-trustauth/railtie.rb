require 'omniauth-trustauth/view_helpers'

module OmniAuth
  module TrustAuth
    class Railtie < Rails::Railtie
      initializer "omniauth-trustauth.view_helpers" do
        ActionView::Base.send :include, ViewHelpers
      end
    end
  end
end
