# SPAroid

Single Packet Authorization client implementation in Ruby, both a library and a CLI app. SPA sends a single encrypted and HMACed UDP package to a server, the server upon receiving it verifies and decrypts it and then executes a command, most often opening the firewall for the client that sent the package. This allows you to employ a reject-all firewall but open the firewall for e.g. SSH access. It's a first line of defence, in the case of 0-day attacks on SSH or similar.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'sparoid'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install sparoid

## Usage

...

Can be used with OpenSSH's ProxyCommand/ProxyUseFdpass to send the packet before connecting, open the TCP connection and that pass that connection back to the SSH client.

```
Host *.example.com
  ProxyCommand sparoid connect %h %p
  ProxyUseFdpass yes
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/84codes/sparoid.rb.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
