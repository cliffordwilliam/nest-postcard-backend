import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { ActiveUser } from 'src/iam/decorators/active-user.decorator';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { CreatePostcardDto } from './dto/create-postcard.dto';
import { UpdatePostcardDto } from './dto/update-postcard.dto';
import { PostcardsService } from './postcards.service';

@Controller('postcards')
export class PostcardsController {
  constructor(private readonly postcardsService: PostcardsService) {}

  @Post()
  create(@Body() createPostcardDto: CreatePostcardDto) {
    return this.postcardsService.create(createPostcardDto);
  }

  @Get()
  findAll(@ActiveUser() user: ActiveUserData) {
    console.log(user);
    return this.postcardsService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.postcardsService.findOne(+id);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updatePostcardDto: UpdatePostcardDto,
  ) {
    return this.postcardsService.update(+id, updatePostcardDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.postcardsService.remove(+id);
  }
}
