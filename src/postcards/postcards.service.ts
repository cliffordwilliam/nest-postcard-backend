import { Injectable } from '@nestjs/common';
import { CreatePostcardDto } from './dto/create-postcard.dto';
import { UpdatePostcardDto } from './dto/update-postcard.dto';

@Injectable()
export class PostcardsService {
  create(createPostcardDto: CreatePostcardDto) {
    return 'This action adds a new postcard';
  }

  findAll() {
    return `This action returns all postcards`;
  }

  findOne(id: number) {
    return `This action returns a #${id} postcard`;
  }

  update(id: number, updatePostcardDto: UpdatePostcardDto) {
    return `This action updates a #${id} postcard`;
  }

  remove(id: number) {
    return `This action removes a #${id} postcard`;
  }
}
