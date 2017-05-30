module DeviseTokenAuth
  class TokenValidationsController < DeviseTokenAuth::ApplicationController
    skip_before_action :assert_is_devise_resource!, :only => [:validate_token,:validate_external_token]
    before_action :set_user_by_token, :only => [:validate_token]
    before_action :set_user_by_external_token, :only => [:validate_external_token]

    def validate_token
      # @resource will have been set by set_user_token concern
      if @resource
        yield @resource if block_given?
        render_validate_token_success
      else
        render_validate_token_error
      end
    end

    def validate_external_token
      # @resource will have been set by set_user_token concern
      if @resource
        render json: {
          success: true,
          data: @resource.as_json(except: [
            :tokens, :created_at, :updated_at
          ])
        }
      else
        render json: {
          success: false,
          errors: ["Invalid login credentials"]
        }, status: 401
      end
    end
    
    protected

    def render_validate_token_success
      render json: {
        success: true,
        data: resource_data(resource_json: @resource.token_validation_response)
      }
    end

    def render_validate_token_error
      render json: {
        success: false,
        errors: [I18n.t("devise_token_auth.token_validations.invalid")]
      }, status: 401
    end
  end
end
