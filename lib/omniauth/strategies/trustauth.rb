require 'omniauth'
require 'openssl'
require 'uri'
require 'multi_json'

module OmniAuth
  module Strategies
    class TrustAuth
      include OmniAuth::Strategy

      option :name, "trustauth"
      option :fields, [:public_key, :authorized]
      option :uid_field, :public_key

      uid do
        raw_info[:name]
      end

      info do
        {
          :name => raw_info[:public_key],
          :public_key => raw_info[:public_key],
          :result => raw_info[:result],
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def request_phase
        session[:authenticating] = false if session[:authenticating].nil?

        if not session[:authenticating]
          session[:authenticating] = true

          user = { :public_key => URI.decode(request.params['public_key']), :random => request.params['random'] }

          result = get_challenge(user)
          session[:server] = result[:server]
          session[:user]   = user
        else
          session[:authenticating] = false

          if not request.params.has_key?('md5') or not request.params.has_key?('sha')
            result = wrong_stage
          else
            user = session[:user]
            user = user.merge({ :md5 => request.params['md5'], :sha => request.params['sha'] })
            result = authenticate(user, session[:server])

            session[:user][:public_key] = user[:public_key]
            session[:user][:result] = result[:status]

            if not result[:status]
              fail!(:invalid_credentials, 'Failed to authorize the public key.')
            end
          end
        end

        Rack::Response.new(MultiJson.encode(result[:json])).finish
      end

      protected

      STATUS = {
        :auth       => 0,
        :auth_fail  => 1,
        :logged_in  => 2,
        :stage_fail => 3,
      }

      PRE_MASTER_SECRET_LENGTH = 48
      SERVER_RANDOM_LENGTH     = 28
      SENDER_CLIENT            = '0x434C4E54'

      MD5_PAD = {
          :pad1 => '363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636',
          :pad2 => '5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c',
      }
      SHA_PAD = {
          :pad1 => '36363636363636363636363636363636363636363636363636363636363636363636363636363636',
          :pad2 => '5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c',
      }

      def raw_info
        @raw_info ||= session[:user]
      end

      def bin2hex(bin)
        bin.unpack('H*')[0]
      end

      def hex2bin(hex)
        Array(hex).pack('H*')
      end

      def wrong_stage
        {
          :status => true,
          :json   => { :status => STATUS[:stage_fail], :error => 'Wrong stage of logging in.' },
        }
      end

      def get_challenge(user)
        user[:public_key] = fix_key(user[:public_key])
        key = OpenSSL::PKey.read user[:public_key]

        pre_master_secret = get_pre_master_secret()
        server_random     = get_server_random()

        encrypted_secret = bin2hex(key.public_encrypt(pre_master_secret))
        encrypted_random = bin2hex(key.public_encrypt(server_random))

        {
          :status => true,
          :json   => { :secret => encrypted_secret, :random => encrypted_random, :status => STATUS[:auth] },
          :server => { :random => server_random, :pre_master_secret => pre_master_secret },
        }
      end

      def authenticate(user, server)
        user[:public_key] = fix_key(user[:public_key])
        key = OpenSSL::PKey.read user[:public_key]

        user_md5 = bin2hex(key.public_decrypt(hex2bin(user[:md5])))
        user_sha = bin2hex(key.public_decrypt(hex2bin(user[:sha])))

        master_secret        = get_master_secret(server[:pre_master_secret], user[:random], server[:random])
        transmitted_messages = get_transmitted_messages(user[:random], master_secret, server[:random])

        md5_hash = get_md5_hash(master_secret, user[:random], server[:random], transmitted_messages)
        sha_hash = get_sha_hash(master_secret, user[:random], server[:random], transmitted_messages)

        success = (md5_hash == user_md5 and sha_hash == user_sha)
        {
          :status => success,
          :json   => {
            :url    => full_host + script_name + callback_path,
            :status => success ? STATUS[:logged_in] : STATUS[:auth_fail],
            :error  => success ? '' : 'Failed to authenticate.',
          },
        }
      end

      def fix_key(key)
        key.gsub! /-----BEGIN PUBLIC KEY-----/, ''
        key.gsub! /-----END PUBLIC KEY-----/, ''
        key.gsub! /\n/,''
        key.gsub!(/ /,'')
        keylines = key.scan(/.{1,65}/)
        "-----BEGIN PUBLIC KEY-----\n" + keylines.join("\n") + "\n-----END PUBLIC KEY-----"
      end

      def get_md5_hash(master_secret, client_random, server_random, transmitted_messages)
        md5(master_secret + MD5_PAD[:pad2] + md5(transmitted_messages + SENDER_CLIENT + master_secret + MD5_PAD[:pad1]))
      end

      def get_sha_hash(master_secret, client_random, server_random, transmitted_messages)
        sha(master_secret + SHA_PAD[:pad2] + sha(transmitted_messages + SENDER_CLIENT + master_secret + SHA_PAD[:pad1]))
      end

      def md5(message)
        bin2hex(OpenSSL::Digest::MD5.digest(message))
      end

      def sha(message)
        bin2hex OpenSSL::Digest::SHA1.digest(message)
      end

      def get_master_secret(pre_master_secret, client_random, server_random)
        md5(pre_master_secret + sha('A' + pre_master_secret + client_random + server_random)) +
        md5(pre_master_secret + sha('BB' + pre_master_secret + client_random + server_random)) +
        md5(pre_master_secret + sha('CCC' + pre_master_secret + client_random + server_random))
      end

      def get_transmitted_messages(client_random, master_secret, server_random)
        client_random + master_secret + server_random
      end

      def get_pre_master_secret
        bin2hex(OpenSSL::Random.random_bytes(PRE_MASTER_SECRET_LENGTH))
      end

      def get_server_random
        current_time = DateTime.now.strftime('%Q').to_i(10) * 10000
        current_time.to_s(16) + bin2hex(OpenSSL::Random.random_bytes(SERVER_RANDOM_LENGTH))
      end
    end
  end
end
