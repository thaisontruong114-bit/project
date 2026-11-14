import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service.js';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(data: {
    name: string;
    email: string;
    pass: string;
    accountType?: 'CUSTOMER' | 'SHOP_OWNER';
    shopName?: string;
  }) {
    const email = data.email?.trim().toLowerCase();
    if (!email || !data.pass || !data.name) {
      throw new BadRequestException('Vui lòng nhập đầy đủ họ tên, email và mật khẩu');
    }

    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new BadRequestException('Email này đã được đăng ký!');
    }

    const hashedPassword = await bcrypt.hash(data.pass, 10);
    const isShopOwner = data.accountType === 'SHOP_OWNER';

    if (isShopOwner && !data.shopName?.trim()) {
      throw new BadRequestException('Vui lòng nhập tên Vựa gạo / Cửa hàng!');
    }

    const newUser = await this.prisma.user.create({
      data: {
        name: data.name.trim(),
        email,
        password: hashedPassword,
        role: isShopOwner ? 'SHOP_OWNER' : 'CUSTOMER',
        ...(isShopOwner
          ? {
              ownedShop: {
                create: {
                  name: data.shopName!.trim(),
                },
              },
            }
          : {}),
      },
    });

    return {
      message: 'Đăng ký tài khoản thành công!',
      userId: newUser.id,
    };
  }

  async login(email: string, pass: string) {
    const normalizedEmail = email?.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user || !(await bcrypt.compare(pass, user.password))) {
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác');
    }

    const payload = {
      sub: user.id,
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }
}
