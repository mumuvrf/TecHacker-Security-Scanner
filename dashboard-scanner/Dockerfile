# ==================================
# Estágio 1: Builder (Cria os arquivos de build estáticos)
# ==================================
FROM node:20-alpine as builder

# Define o diretório de trabalho no container
WORKDIR /app

# Copia os arquivos de configuração de dependência
# Copia package.json e package-lock.json (ou yarn.lock)
COPY package*.json ./

# Instala as dependências do Node
RUN npm install

# Copia o restante do código fonte do front-end
COPY . .

# Roda o comando de build do Vite. Isso gera a pasta 'dist'.
# Certifique-se de que o seu package.json tem o script 'build'.
RUN npm run build

# ==================================
# Estágio 2: Produção (Servir com Nginx)
# ==================================
FROM nginx:stable-alpine as production

# Copia a saída do build do estágio anterior (a pasta 'dist')
# O Nginx serve arquivos estáticos a partir de /usr/share/nginx/html
COPY --from=builder /app/dist /usr/share/nginx/html

# Expõe a porta 80, a porta padrão do Nginx
EXPOSE 80

# O Nginx já é o comando de inicialização padrão (CMD)
# Não é necessário adicionar um CMD, ele já iniciará o servidor