module OmniAuth
  module TrustAuth
    module ViewHelpers
      def trustauth_url
        tag 'meta', :name => 'trustauth', :content => defined?(user_omniauth_authorize_path) ? user_omniauth_authorize_path(:trustauth) : '/auth/trustauth'
      end
    end
  end
end
