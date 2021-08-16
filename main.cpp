/*
*   CIC0201 - Segurança Computacional – 2021/1 Prof. João Gondim 
*   Aluno: Lucas Araújo Pena | 13/0056162
*
*               Trabalho de Implementação 1 
*                   Cifra de Vigenere
*
*/


#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>

#include "Vigenere.h"

#define LOG(X) std::cout<< "\n " << X << std::endl;


int main() {

    // Lendo Arquivos texto
    std::ifstream fin_cryptogram("cryptogram.txt");           // Lendo o criptograma
    std::ifstream fin_pass("password.txt");                 // Lendo a senha
    std::ifstream fin_message("message.txt");               // Lendo a mensagem

    // Para pegar erros
    //fin_cryptogram.exceptions( std::ifstream::badbit | std::ifstream::failbit );
    //fin_message.exceptions( std::ifstream::badbit  | std::ifstream::failbit );

    std::string cryptogram = "";                             // Criptograma do arquivo
    std::string password = "";                               // Senha do arquivo
    std::string message = "";                                // Mensagem decifrada
    std::string temp = "";

    Vigenere vigenere;

    // Checa se os arquivos foram carregados
    if( !fin_cryptogram ) {

        std::cerr << "\n Erro ao abrir criptograma \n\n" << std::endl;
        std::cin.ignore();
        return -1;

    }

    if( !fin_pass ) {

        std::cerr << "\n Erro ao abrir senha \n\n" << std::endl;
        std::cin.ignore();
        return -1;

    }

    if( !fin_message ) {

        std::cerr << "\n Erro ao abrir mensagem \n\n" << std::endl;
        std::cin.ignore();
        return -1;

    }

    // Passa os dados dos arquivos para o programa
    fin_pass >> password;

    // Pega todo o conteúdo do arquivo, incluíndo espaços
    try {
        while ( std::getline( fin_cryptogram, temp ) ) {

            cryptogram += temp += '\n';

        }
    }
    catch( std::ifstream::failure e ) {

        std::cerr << "\n Erro ocorreu (cryptogram): " << e.what() << "\n"
                  << "\n failbit: " << fin_cryptogram.fail()
                  << "\n neofbit: " << fin_cryptogram.eof()
                  << "\n badbit: "  << fin_cryptogram.bad() << std::endl;

    }

    temp = "";

    try {
        while ( std::getline( fin_message, temp ) ){

            message += temp += '\n';

        }
    }
    catch( std::ifstream::failure e ) {

        std::cerr << "\n Erro ocorreu (message): " << e.what() << '\n'
                  << "\n failbit: " << fin_message.fail()
                  << "\n neofbit: " << fin_message.eof()
                  << "\n badbit: "  << fin_message.bad() << "\n\n";

    }

    // Transforma o criptograma e a mensagem para caixa alta
    std::transform(cryptogram.begin(), cryptogram.end(), cryptogram.begin(), ::toupper);
    std::transform(message.begin(), message.end(), message.begin(), ::toupper);

    // Passa para frente os dados adquiridos
    vigenere.SetValues( message, cryptogram, password );

    // Caso não haja criptograma, será chamada a função de criptografar
    if ( vigenere.GetCryptogram() == "" && vigenere.GetPassword() != "" && vigenere.GetMessage() != "" ) {

        try {

            vigenere.ExtendKey( vigenere.GetMessage() );
            vigenere.Cipher();
            std::cout << "\n Cifra realizada" << std::endl;

        }

        catch (...) {

            std::cout << "\n Erro ao realizar a cifra" << std::endl;

        }


    }

    // Caso haja Criptograma, será chamada a função de decifrar
    else if( vigenere.GetCryptogram() != "" && vigenere.GetPassword() != "" && vigenere.GetMessage() == "" ) {

        try {

            vigenere.ExtendKey( vigenere.GetCryptogram() );
            vigenere.Decryption();
            std::cout << "\n Decifracao realizada" << std::endl;

        }

        catch( ... ) {

            std::cerr << "\n Erro ao realizar decifracao" << std::endl;

        }

    }

    // Caso haja somente o Criptograma, será chamada a função de quebrar o criptograma
    else if( vigenere.GetCryptogram() != "" && vigenere.GetPassword() == "" && vigenere.GetMessage() == "" ) {

        try {

            //vigenere.FindPassword();
            std::cout << "\n Decifracao realizada" << std::endl;

        }

        catch( ... ) {

            std::cerr << "\n Erro ao realizar decifracao" << std::endl;

        }

    }

    else {

        std::cout << "\n Nao eh possivel realizar nenhuma operacao. \n\n" << std::endl;
        return 0;

    }

    // Saída de Dados
    try{

        message = vigenere.GetMessage();
        cryptogram = vigenere.GetCryptogram();

        std::ofstream fout("log.txt");

        fout << "[Senha] \n\n"       << password   << "\n\n" << std::endl
             << "[Criptograma] \n\n" << cryptogram << "\n\n" << std::endl
             << "[Mensagem] \n\n"    << message;

        fout.close();

        std::cout << "\n Programa executado com sucesso" << std::endl;
        std::cout << " Visualizar log.txt \n" << std::endl;

     }
     catch( ... ) {

         std::cerr << "\n Erro ao criar arquivo log \n\n";

     }

    // Segura o console aberto
    std::cin.ignore();

    return 0;

}