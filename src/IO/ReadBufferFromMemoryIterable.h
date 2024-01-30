#pragma once

#include <string>
#include <string_view>
#include <IO/ReadBuffer.h>


namespace DB
{

namespace ReadBufferFromMemoryIterableDetails
{

template <class E> const char * get_element_data(const E & element);
template <class E> size_t get_element_size(const E & element);

}

 /** Same as ReadBufferFromMemory, but accept multiple buffers that will be feeded one after another.
  *  Used where you feed line by line for faster processing.
  */
template <class It>
class ReadBufferFromMemoryIterable : public ReadBuffer
{
public:
    ReadBufferFromMemoryIterable(It & begin_, It end_)
        : ReadBuffer(nullptr, 0)
        , it(begin_)
        , end(end_)
    {}

    bool nextRow() override
    {
        ++it;
        is_eof = false;
        return it != end;
    }

    bool nextImpl() override
    {
        if (it == end)
            return false;
        if (is_eof == true)
            return false;

        BufferBase::set(
            const_cast<char *>(ReadBufferFromMemoryIterableDetails::get_element_data(*it)),
            ReadBufferFromMemoryIterableDetails::get_element_size(*it),
            0);
        is_eof = true;

        return true;
    }

private:
    It & it;
    It end;
    bool is_eof = false;
};

}
