module DeviseTokenAuth
  class TokenValidationsController < DeviseTokenAuth::ApplicationController
    skip_before_filter :assert_is_devise_resource!, :only => [:validate_token,:validate_external_token]
    before_filter :set_user_by_token, :only => [:validate_token]
    before_filter :set_user_by_external_token, :only => [:validate_external_token]

    def validate_token
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

  end
end
