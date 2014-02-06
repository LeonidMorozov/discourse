require_dependency "auth/current_user_provider"

class Auth::OpenedCurrentUserProvider
	include ActionController::HttpAuthentication::Token

  CURRENT_USER_KEY ||= "_OPENED_CURRENT_USER"
  API_KEY ||= "_OPENED_API"
  TOKEN_COOKIE ||= "_o"

  # do all current user initialization here
  def initialize(env)
    @env = env
    @request = Rack::Request.new(env)
  end

  # our current user, return nil if none is found
  def current_user
    return @env[CURRENT_USER_KEY] if @env.key?(CURRENT_USER_KEY)

    request = ActionDispatch::Request.new(@env)
    auth_token = token_and_options(request)
		auth_token = auth_token[0] if auth_token.kind_of?(Array) and auth_token.any?

    current_user = nil

    if auth_token && auth_token.length == 32
      current_user = User.where(auth_token: auth_token).first
      unless current_user
	      opened_user = get_opened_user auth_token
	      if opened_user
		      current_user = User.where(username_lower: opened_user['username'].downcase).first
					unless current_user
						new_user = User.new username: opened_user['username'], email: opened_user['email']
						if new_user.save
							current_user = new_user
						end
					end
	      end
			end
      current_user.update_auth_token!(auth_token) if current_user
    end

    if current_user
      current_user.update_last_seen!
      current_user.update_ip_address!(request.ip)
    end

    @env[CURRENT_USER_KEY] = current_user
  end

  def get_opened_user(token)
		headers = {
				'AUTHORIZATION' => ActionController::HttpAuthentication::Token.encode_credentials(token)
		}
		url = ENV['opened_auth_endpoint'].present? ? ENV['opened_auth_endpoint'] : 'http://localhost:3001/current_user.json'
		response = RestClient.get url, headers
		if response.code == 200
			JSON.parse(response.to_str)['current_user']
		else
			nil
		end
  end

	def log_on_user(user, session, cookies)
    make_developer_admin(user)
    @env[CURRENT_USER_KEY] = user
  end

  def make_developer_admin(user)
    if  user.active? &&
        !user.admin &&
        Rails.configuration.respond_to?(:developer_emails) &&
        Rails.configuration.developer_emails.include?(user.email)
      user.update_column(:admin, true)
    end
  end

  def log_off_user(session, cookies)
    cookies[TOKEN_COOKIE] = nil
  end


  # api has special rights return true if api was detected
  def is_api?
    current_user
    @env[API_KEY]
  end

  def has_auth_cookie?
    request = Rack::Request.new(@env)
    cookie = request.cookies[TOKEN_COOKIE]
    !cookie.nil? && cookie.length == 32
  end
end
