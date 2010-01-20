require 'rubygems'

require 'base64'
require 'digest/sha1'
require 'haml'
require 'ldap'
require 'sinatra'

include Rack::Utils

LDAP_HOST = 'localhost'
LDAP_PORT = 389
LDAP_BASEDN = 'o=Example'

DN_SEARCH_FILTER_TEMPLATE = '(&(|(uid=#{user_id})(mail=#{user_id})(alternateAddress=#{user_id}))(accountStatus=active))'

get '/' do
 haml :password
end

post '/' do
  user_id = params[:user_id]
  password_old = params[:password_old]
  password_new_1 = params[:password_new_1]
  password_new_2 = params[:password_new_2]

  begin
    if password_new_1 != password_new_2
      raise "New passwords need to be the same."
    end

    e_digest = Digest::SHA1.digest(password_new_1)
    e_base64 = Base64.encode64(e_digest).chomp
    e_password = "{SHA}" + e_base64

    passwordChange = [
      LDAP.mod(LDAP::LDAP_MOD_REPLACE, "userPassword", [e_password]),
    ]

    conn = LDAP::Conn.new(host = LDAP_HOST, port = LDAP_PORT)
    conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, LDAP::LDAP_VERSION3)

    dnSearchFilter = eval('"' + DN_SEARCH_FILTER_TEMPLATE + '"')

    dn = []
    conn.search(LDAP_BASEDN, LDAP::LDAP_SCOPE_SUBTREE, dnSearchFilter, ['dn']) { |entry|
      dn << entry.dn
    }

    if dn.length > 1
      raise "There is more than one user with this email address."
    end

    conn.bind(dn[0], password_old) do
      conn.modify(dn[0], passwordChange)
    end
  rescue Exception => e
    @message = "Unable to change your password."
  end

  if @message
    haml :password
  else
    haml :password_changed
  end
end
