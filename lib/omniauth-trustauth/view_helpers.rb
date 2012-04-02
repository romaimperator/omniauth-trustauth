module OmniAuth
  module TrustAuth
    module ViewHelpers
      def trustauth_url
        tag 'meta', :name => 'trustauth', :content => user_omniauth_authorize_path(:trustauth)
      end
    end
  end
end
