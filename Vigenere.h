#pragma once

#include <string>

class Vigenere {

public:

    Vigenere() noexcept {}
    ~Vigenere() noexcept {}

    void const Cipher() noexcept {

        std::string result = "";

        for( int i = 0; i < m_message.size(); i++ ) {

            // Se for uma letra entre A e Z | 'A' -> 65 [ASCII]
            if( (char)m_message[i] >= 'A' && (char)m_message[i] <= 'Z' )
                // (# da linha + # da coluna) % 26 = valor da célula
                result += (( (char)m_message[i] - 'A' + (char)m_password[i] - 'A' ) % 26) + 'A';

            // Se não for, retorna ela mesma. Para espaços e pontuações.
            else
                result += m_message[i];

        }

        m_cryptogram = result;

    }

    void const Decryption() noexcept {

        std::string result = "";

        for( int32_t i = 0; i < m_cryptogram.size(); i++ ) {


            // Se for uma letra entre A e Z
            if( (char)m_cryptogram[i] >= 'A' && (char)m_cryptogram[i] <= 'Z' )
                // (# da célula - # da coluna + 26) % 26 = # da linha
                result += ((( (char)m_cryptogram[i] - 'A' - ( (char)m_password[i] - 'A' ) ) + 26 ) % 26) + 'A';

            // Se não for, retorna ela mesma. Para espaços e pontuações.
            else
                result += m_cryptogram[i];

        }

        m_message = result;

    }

    // Extende a senha, caso necessário
    void const ExtendKey( std::string input_text ) noexcept {

        // Caso a senha seja do mesmo tamanho ou maior, retorna ela mesma
        if( m_password.size() < input_text.size() ) {

            int32_t remaining_size = input_text.size() - m_password.size();
            int32_t password_size = m_password.size();

            // Repete a senha até preencher o espaço
            while( remaining_size >= password_size ) {

                m_password += m_password;
                remaining_size -= password_size;
                password_size = m_password.size();

            }

            // Corta a repetição no tamanho da mensagem
            m_password += m_password.substr( 0, remaining_size );

        }

    }

    void const FindPassword( std::string cryptogram ) noexcept;

    void const SetValues( std::string message, std::string cryptogram, std::string password ) noexcept {

        m_message = message;
        m_cryptogram = cryptogram;
        m_password = password;

    }

    std::string const GetMessage() const noexcept    { return m_message; }
    std::string const GetCryptogram() const noexcept { return m_cryptogram; }
    std::string const GetPassword() const noexcept   { return m_password; }

private:

    std::string m_message;
    std::string m_cryptogram;
    std::string m_password;

};