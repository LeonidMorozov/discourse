class OptionsRequestController < ApplicationController
  layout false
  skip_before_filter :redirect_to_login_if_required

  # respond to options requests with blank text/plain as per spec
  def cors_preflight_check
	  logger.info ">>> responding to CORS request"
	  render nothing: true
  end
end
