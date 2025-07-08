Web Vulnerability Scanner é uma ferramenta de segurança para detectar vulnerabilidades comuns em aplicações web, desenvolvida em Python.

🚀 Funcionalidades
✅ Detecção de SQL Injection

✅ Identificação de vulnerabilidades XSS

✅ Verificação de Open Redirects

✅ Interface colorida no terminal

✅ Modo de testes automáticos

📥 Instalação
Clone o repositório:


git clone https://github.com/seu-usuario/tehry-scanner.git
cd tehry-scanner

Instale as dependências:


pip install -r requirements.txt

🛠️ Como Usar

Escaneamento básico:


python tehry_scanner.py http://exemplo.com
Modo de testes (sites vulneráveis de demonstração):


python tehry_scanner.py --test
Opções disponíveis:


--test    Executa testes em sites de demonstração vulneráveis
--help    Mostra esta mensagem de ajuda

🌐 Sites de Teste Recomendados
Para fins educacionais:

http://testphp.vulnweb.com

http://demo.testfire.net

⚠️ Aviso Legal
Este software deve ser usado APENAS para:

Testes em seus próprios sistemas

Ambientes com permissão explícita

Fins educacionais e de pesquisa

Não me responsabilizo por uso indevido desta ferramenta.

📌 Requisitos
Python 3.6+

Bibliotecas: requests, colorama

🤝 Como Contribuir
Faça um Fork do projeto

Crie sua branch (git checkout -b feature/AmazingFeature)

Commit suas mudanças (git commit -m 'Add some AmazingFeature')

Push para a branch (git push origin feature/AmazingFeature)

Abra um Pull Request
