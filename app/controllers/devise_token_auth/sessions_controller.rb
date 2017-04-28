# see http://www.emilsoman.com/blog/2013/05/18/building-a-tested/
module DeviseTokenAuth
  class SessionsController < DeviseTokenAuth::ApplicationController
    before_action :set_user_by_token, :only => [:destroy]
    after_action :reset_session, :only => [:destroy]

    def new
      render_new_error
    end

    def create
      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(:email)
        email = resource_params[:email].downcase
      else
        email = resource_params[:email]
      end
      provider=resource_params[:provider]

      q = provider == "email" ? "uid='#{email}' AND provider='#{provider}'" : "uid='#{provider}@#{email}' AND provider='#{provider}'"

      if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
        q = provider == "email" ? "BINARY uid='#{email}' AND provider='#{provider}'" : "BINARY uid='#{provider}@#{email}' AND provider='#{provider}'"
      end
      
      @resource = resource_class.where(q).first
      
      if @resource and valid_params? and @resource.valid_password?(resource_params[:password]) and @resource.confirmed?
        # create client id
        @client_id = SecureRandom.urlsafe_base64(nil, false)
        @token     = SecureRandom.urlsafe_base64(nil, false)
        @external_token = SecureRandom.urlsafe_base64(nil, false)
        
        @resource.tokens[@client_id] = {
          token: BCrypt::Password.create(@token),
          external_token: BCrypt::Password.create(@external_token),
          expiry: (Time.now + DeviseTokenAuth.token_lifespan).to_i
        }
        @resource.save

        sign_in(:user, @resource, store: false, bypass: false)
        if @resource.class.to_s == 'Agent'
          LoginBitacoraAgent.create(
            :agency_id => @resource.agency_id,
            :profile_id => @resource.profile_id,
            :agent_id =>@resource.id,
            :email =>@resource.email,
            :is_owner =>@resource.is_owner,
            :sign_in_ip =>@resource.current_sign_in_ip,
            :action_type =>LoginBitacoraAgent.action_types[:sign_in]
            )
          render json: {
            data: @resource.as_json(only: [
              :id,
              :email,
              :provider,
              :uid,
              :agency_id,
              :name,
              :last_name,
              :is_owner,
              :avatar_file_name,
              :avatar_content_type,
              :telephone,
              :admin_license,
              :sign_in_count],include: {agency: {  
                except:[:sabre_ipcc,:sabre_password,:sabre_username]},
                profile:{ 
                  include: { functionalities:{} 
                }  
              }
              }).merge("external_token" => {client:@client_id, token: @external_token  })
          }
        else
          render json: {
            data: @resource.as_json(except: [
              :tokens, :created_at, :updated_at
              ])
          }
        end

      elsif @resource and not @resource.confirmed?
        render json: {
          success: false,
          errors: [
            "A confirmation email was sent to your account at #{@resource.email}. "+
            "You must follow the instructions in the email before your account "+
            "can be activated"
          ]
        }, status: 401
        render_create_success
      elsif @resource && !(!@resource.respond_to?(:active_for_authentication?) || @resource.active_for_authentication?)
        render_create_error_not_confirmed
      else
        render_create_error_bad_credentials
      end
    end

    def destroy
      # remove auth instance variables so that after_action does not run
      user = remove_instance_variable(:@resource) if @resource
      client_id = remove_instance_variable(:@client_id) if @client_id
      remove_instance_variable(:@token) if @token

      if user and client_id and user.tokens[client_id]

        if user.class.to_s == 'Agent'
          LoginBitacoraAgent.create(
          :agency_id => user.agency_id,
          :profile_id => user.profile_id,
          :agent_id =>user.id,
          :email =>user.email,
          :is_owner =>user.is_owner,
          :sign_in_ip =>user.current_sign_in_ip,
          :action_type =>LoginBitacoraAgent.action_types[:sign_out]
          )
        end
        user.tokens.delete(client_id)
        user.save!

        yield user if block_given?

        render_destroy_success
      else
        render_destroy_error
      end
    end

    protected

    def valid_params?(key, val)
      resource_params[:password] && key && val
    end

    def get_auth_params
      auth_key = nil
      auth_val = nil

      # iterate thru allowed auth keys, use first found
      resource_class.authentication_keys.each do |k|
        if resource_params[k]
          auth_val = resource_params[k]
          auth_key = k
          break
        end
      end

      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(auth_key)
        auth_val.downcase!
      end

      return {
        key: auth_key,
        val: auth_val
      }
    end

    def render_new_error
      render json: {
        errors: [ I18n.t("devise_token_auth.sessions.not_supported")]
      }, status: 405
    end

    def render_create_success
      render json: {
        data: resource_data(resource_json: @resource.token_validation_response)
      }
    end

    def render_create_error_not_confirmed
      render json: {
        success: false,
        errors: [ I18n.t("devise_token_auth.sessions.not_confirmed", email: @resource.email) ]
      }, status: 401
    end

    def render_create_error_bad_credentials
      render json: {
        errors: [I18n.t("devise_token_auth.sessions.bad_credentials")]
      }, status: 401
    end

    def render_destroy_success
      render json: {
        success:true
      }, status: 200
    end

    def render_destroy_error
      render json: {
        errors: [I18n.t("devise_token_auth.sessions.user_not_found")]
      }, status: 404
    end


    private

    def resource_params
      params.permit(*params_for_resource(:sign_in))
    end

  end
end
