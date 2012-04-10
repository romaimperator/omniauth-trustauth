# OmniAuth::TrustAuth

This gem is an OmniAuth strategy to support TrustAuth authentication.

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth-trustauth'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-trustauth

## Usage

1. First edit your layout.

    ```erb
    <!-- app/views/layouts/application.html.erb -->
    <!DOCTYPE html>
    <html>
    <head>
      <title>Your Title</title>
      <%= stylesheet_link_tag    "application", :media => "all" %>
      <%= javascript_include_tag "application" %>
      <%= csrf_meta_tags %>
      <%= trustauth_url %> <!-- Add this line to your layout to allow logging in from any page. -->
    </head>
    <body>
    ...
    ```

2. Add your handler for the OmniAuth callback. Here's an example of
   something simple:

    ```ruby
    # your trustauth callback handler
    def trustauth
      #if the user was authenticated
      if auth_hash['info']['result']
        # see if this user has an account
        user = User.find_by_public_key(auth_hash['info']['public_key'])

        if not user
          # This user doesn't have an account so save the public key and redirect them to the page to enter an email.
          session[:public_key] = auth_hash['info']['public_key']
          redirect_to new_user_path and return
        else
          # Sign in the user if they aren't signed in
          if not user_signed_in?
            sign_in_and_redirect(:user, user) and return
          end
        end
      else
        # Authentication of the public key failed so redirect and notify the user
        redirect_to root_path, :notice => "Authentication failed."
      end
    end

    def auth_hash
      request.env['omniauth.auth']
    end
    ```

3. You will need to store the public key somewhere in order to let users
   sign in with it. Be sure to make this column unique.

    ```ruby
    # db/migrate/AddPublicKey.rb
    class AddPublicKey < ActiveRecord::Migration
      def up
        add_column :users, :public_key, :text, :unique => true
      end

      def down
        remove_column :users, :public_key
      end
    end
    ```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
