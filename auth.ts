import prisma from "@/lib/prisma"
import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import GitHub from "next-auth/providers/github"
import { PrismaAdapter } from "@auth/prisma-adapter"


export const { auth, handlers, signIn, signOut } = NextAuth({ 
    adapter : PrismaAdapter(prisma),
    providers: [GitHub, 
    Credentials({
        credentials :{
            email: {},
            password : {}
        },
        authorize : async(credentials) => {
            const user = await prisma.user.findFirst({
                where:{email: credentials.email as string, password: credentials.password as string}
            })
            if(!user){
                throw new Error("Invalid credentials")
            }else{
                return user
            }
        }
    })
] })