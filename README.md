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

2. Add your handler for the OmniAuth callback. Here's an example of
   something simple:

```ruby
# your trustauth callback handler
def trustauth
  # if the user was authenticated
  if auth_hash['info']['result']
    # find the public key in the database or create a new user
    user = User.find_or_create_by_public_key(auth_hash['info']['public_key'])

    # login if the user isn't logged in
    if not user_signed_in?
      sign_in_and_redirect(:user, user)
    end
  end
  redirect_to root_path
end

def auth_hash
  request.env['omniauth.auth']
end

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
